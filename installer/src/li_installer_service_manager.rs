// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use crate::li_installer_arguments::{ControlAddressSelection, InstallerArguments};
use crate::li_installer_core_manager::CoreInstallResult;
use crate::li_installer_display_manager::DisplayManager;
use crate::li_installer_probe_manager::ProbeFacts;

const WATCHDOG_PROTECTION_ROOT_NAME: &str = "protected-placements";
const PAIRING_TRUST_WORKSPACE_NAME: &str = "pairing_trust_staging";
const RUNTIME_CATALOG_SOURCE: &str =
    "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json";
const CORE_SETUP_EXIT_COMMITTED: i32 = 0;
const CORE_SETUP_EXIT_SAFE_TO_ROLLBACK: i32 = 2;
const CORE_SETUP_EXIT_RECOVERY_REQUIRED: i32 = 3;
const CORE_SETUP_RESULT_SCHEMA_NAME: &str = "li_core_setup_result";
const CORE_SETUP_RESULT_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_CORE_SETUP_OUTPUT_BYTES: usize = 32 * 1024;
const MAXIMUM_CORE_SETUP_ERROR_BYTES: usize = 4 * 1024 * 1024;
const SETUP_DISPLAY_NAME: &str = "Let's Infer Node";
const SETUP_ROLE: &str = "main";
const SETUP_NODE_PRIVATE_HOST: &str = "0.0.0.0";
const SETUP_NODE_PRIVATE_PORT: u16 = 9_443;
const SETUP_GATEWAY_PRIVATE_HOST: &str = "0.0.0.0";
const SETUP_GATEWAY_PRIVATE_PORT: u16 = 9_444;
const SETUP_GATEWAY_PUBLIC_HOST: &str = "0.0.0.0";
const SETUP_GATEWAY_PUBLIC_PORT: u16 = 8000;
const SETUP_WATCHDOG_HOST: &str = "127.0.0.1";
const SETUP_WATCHDOG_PORT: u16 = 9_445;
const HOME_QUARANTINE_ATTEMPTS: u64 = 32;
static HOME_QUARANTINE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PRIVATE_DIRECTORY_UMASK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Holds the only installer umask authority until one native directory creation completes.
struct PrivateDirectoryUmaskGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: libc::mode_t,
}

impl PrivateDirectoryUmaskGuard {
    // Serializes the process-global umask change and restricts it to one mkdirat invocation.
    fn acquire() -> Result<Self, String> {
        let lock = PRIVATE_DIRECTORY_UMASK
            .lock()
            .map_err(|_| "Core setup private creation lock is unavailable".to_string())?;
        let previous = unsafe { libc::umask(0o077) };
        Ok(Self {
            _lock: lock,
            previous,
        })
    }
}

impl Drop for PrivateDirectoryUmaskGuard {
    // Restores the caller's exact umask before releasing serialized creation authority.
    fn drop(&mut self) {
        unsafe { libc::umask(self.previous) };
    }
}

// Stores the verified user-facing result returned by Core setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupSummary {
    pub api_key_file: Option<String>,
    pub display_name: String,
    pub inference_endpoint: Option<String>,
    pub role: String,
}

// Stores every caller-known value that must bind one successful Core result to this request.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedSetupResult {
    api_key_file: Option<String>,
    control_address: String,
    display_name: String,
    inference_endpoint: Option<String>,
    role: String,
    services: Vec<String>,
}

// Decodes only the complete current Core setup result vocabulary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreSetupResultDocument {
    schema: CoreSetupResultSchemaDocument,
    status: CoreSetupResultDisposition,
    node_id: String,
    machine_id: String,
    installation_id: String,
    display_name: String,
    role: String,
    control_address: String,
    api_key_file: RequiredOptionalString,
    inference_endpoint: RequiredOptionalString,
    services: Vec<String>,
}

// Decodes the exact nested Core setup result schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreSetupResultSchemaDocument {
    name: String,
    version: u32,
}

// Restricts a successful result to an initial commit or exact committed replay.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CoreSetupResultDisposition {
    Installed,
    Replayed,
}

// Requires one nullable string field to remain present in the closed result object.
#[derive(Deserialize)]
#[serde(transparent)]
struct RequiredOptionalString(Option<String>);

// Distinguishes an activation-safe setup rejection from an ambiguous committed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceSetupError {
    SafeToRollback(String),
    RecoveryRequired(String),
}

impl ServiceSetupError {
    // Creates one failure proven to precede Core mutation or follow exact durable compensation.
    fn safe_to_rollback(reason: impl Into<String>) -> Self {
        Self::SafeToRollback(reason.into())
    }

    // Creates one failure whose service-transaction commit state must be reconciled.
    fn recovery_required(reason: impl Into<String>) -> Self {
        Self::RecoveryRequired(reason.into())
    }

    // Returns whether the installed Core activation may be reversed without hiding a commit.
    pub const fn may_rollback_activation(&self) -> bool {
        matches!(self, Self::SafeToRollback(_))
    }

    // Transfers the stable diagnostic into the installer display boundary.
    pub fn into_message(self) -> String {
        match self {
            Self::SafeToRollback(reason) | Self::RecoveryRequired(reason) => reason,
        }
    }
}

impl fmt::Display for ServiceSetupError {
    // Presents the stable setup diagnostic without exposing the rollback decision as text policy.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SafeToRollback(reason) | Self::RecoveryRequired(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

// Stores one immutable shell-free Core setup command for exact reconciliation replay.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreSetupCommand {
    arguments: Vec<std::ffi::OsString>,
    executable: PathBuf,
}

impl CoreSetupCommand {
    // Creates one fixed executable and argument vector before any setup process starts.
    fn new(executable: PathBuf, arguments: Vec<std::ffi::OsString>) -> Self {
        Self {
            arguments,
            executable,
        }
    }
}

// Carries one exact native process status and bounded-stream candidates for policy classification.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreSetupProcessOutput {
    status: Option<i32>,
    stderr: Vec<u8>,
    stdout: Vec<u8>,
}

// Exposes only the stdin and completion operations required after a successful spawn.
trait CoreSetupChildProcess: Send {
    // Writes and closes the complete exact setup input document.
    fn write_input(&mut self, input: &[u8]) -> Result<(), String>;

    // Waits for process completion and returns its exact status and captured streams.
    fn wait(self: Box<Self>) -> Result<CoreSetupProcessOutput, String>;
}

// Spawns one platform-native Core setup process from an already-fixed command.
trait CoreSetupProcessSpawner: Send + Sync {
    // Starts the exact command with isolated standard streams and no shell.
    fn spawn(&self, command: &CoreSetupCommand) -> Result<Box<dyn CoreSetupChildProcess>, String>;
}

// Revalidates the pinned setup home immediately before every native process spawn.
struct AuthorizedCoreSetupProcessSpawner<'a> {
    delegate: &'a dyn CoreSetupProcessSpawner,
    home: &'a Path,
    preparation: &'a SetupRootPreparation,
}

impl CoreSetupProcessSpawner for AuthorizedCoreSetupProcessSpawner<'_> {
    // Refuses to start or replay Core setup after any lexical home identity drift.
    fn spawn(&self, command: &CoreSetupCommand) -> Result<Box<dyn CoreSetupChildProcess>, String> {
        self.preparation.validate_lexical_home(self.home)?;
        self.delegate.spawn(command)
    }
}

// Owns one native Core setup child after the exact command has started.
struct SystemCoreSetupChildProcess {
    child: Child,
}

impl CoreSetupChildProcess for SystemCoreSetupChildProcess {
    // Writes the exact document and closes stdin on success or failure before returning.
    fn write_input(&mut self, input: &[u8]) -> Result<(), String> {
        let mut stdin = self
            .child
            .stdin
            .take()
            .ok_or_else(|| "Core setup input is unavailable".to_string())?;
        stdin
            .write_all(input)
            .map_err(|_| "Core setup input could not be written".to_string())
    }

    // Invokes the native completion wait and translates only its exact observed process facts.
    fn wait(self: Box<Self>) -> Result<CoreSetupProcessOutput, String> {
        let output = self
            .child
            .wait_with_output()
            .map_err(|error| format!("Core setup could not finish: {error}"))?;
        Ok(CoreSetupProcessOutput {
            status: output.status.code(),
            stderr: output.stderr,
            stdout: output.stdout,
        })
    }
}

// Performs the ordinary shell-free native spawn without owning setup outcome policy.
#[derive(Default)]
struct SystemCoreSetupProcessSpawner;

impl CoreSetupProcessSpawner for SystemCoreSetupProcessSpawner {
    // Starts one exact command with private pipes for the machine protocol.
    fn spawn(&self, command: &CoreSetupCommand) -> Result<Box<dyn CoreSetupChildProcess>, String> {
        let mut native = Command::new(&command.executable);
        native
            .args(&command.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = native
            .spawn()
            .map_err(|error| format!("Core setup could not run: {error}"))?;
        Ok(Box::new(SystemCoreSetupChildProcess { child }))
    }
}

// Names the complete first-attempt or reconciled setup process outcome.
enum CoreSetupProtocolResult {
    NotStarted(String),
    Committed(SetupSummary),
    SafeToRollback(String),
    ReconciliationRequired {
        committed_seen: bool,
        reason: String,
    },
    RecoveryRequired(String),
}

// Binds one created child name to the exact native directory identity owned by this attempt.
struct CreatedSetupDirectory {
    device: u64,
    inode: u64,
    name: &'static str,
    parent: SetupDirectoryParent,
}

// Selects the exact already-opened parent descriptor for one setup-owned directory.
#[derive(Clone, Copy)]
enum SetupDirectoryParent {
    Core,
    Home,
}

// Binds one fresh installation home to its exact parent entry and native identity.
struct CreatedSetupHome {
    created_parents: Vec<CreatedSetupParent>,
    device: u64,
    inode: u64,
    name: CString,
    parent: File,
    phase: CreatedSetupHomePhase,
    quarantine: Option<CreatedHomeQuarantine>,
}

// Names the exact durable cleanup boundary retained after each successful native mutation.
#[derive(Clone, Copy, Eq, PartialEq)]
enum CreatedSetupHomePhase {
    Claimed,
    Quarantined,
    HomeRemoved,
    QuarantineRemoved,
    HomeRetired,
}

// Retains one exact quarantine descriptor and parent-entry identity across cleanup retries.
struct CreatedHomeQuarantine {
    device: u64,
    directory: File,
    inode: u64,
    name: CString,
}

// Binds one installer-created home ancestor to its retained parent and exact native identity.
struct CreatedSetupParent {
    device: u64,
    inode: u64,
    name: CString,
    parent: File,
}

// Returns either a validated replay or one exact newly created private directory identity.
enum PrivateDirectoryClaim {
    Existing(File),
    Created {
        device: u64,
        directory: File,
        inode: u64,
    },
}

// Selects one deterministic post-mkdir native boundary for orphan-compensation tests.
#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PrivateDirectoryFailurePoint {
    BeforeMetadata,
    BeforeOpen,
    AfterCreate,
    AfterOpen,
    BeforeSync,
}

#[cfg(test)]
std::thread_local! {
    static PRIVATE_DIRECTORY_FAILURE: std::cell::RefCell<Option<(&'static str, PrivateDirectoryFailurePoint)>> = const { std::cell::RefCell::new(None) };
}

// Installs one thread-confined creation failure consumed only by its exact label and boundary.
#[cfg(test)]
fn inject_private_directory_failure(label: &'static str, point: PrivateDirectoryFailurePoint) {
    PRIVATE_DIRECTORY_FAILURE.with(|failure| {
        assert!(failure.replace(Some((label, point))).is_none());
    });
}

// Consumes one exact thread-confined creation failure without affecting parallel tests.
#[cfg(test)]
fn take_private_directory_failure(label: &str, point: PrivateDirectoryFailurePoint) -> bool {
    PRIVATE_DIRECTORY_FAILURE.with(|failure| {
        let matches = failure
            .borrow()
            .as_ref()
            .is_some_and(|expected| expected.0 == label && expected.1 == point);
        if matches {
            failure.replace(None);
        }
        matches
    })
}

// Selects one exact fresh-home cleanup publication boundary for replay tests.
#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum FreshHomeCleanupFailurePoint {
    AfterHomeUnlink,
    AfterRename,
    BeforeParentCleanup,
    DuringTraversal,
}

#[cfg(test)]
std::thread_local! {
    static FRESH_HOME_CLEANUP_FAILURE: std::cell::RefCell<Option<FreshHomeCleanupFailurePoint>> = const { std::cell::RefCell::new(None) };
}

// Installs one thread-confined cleanup failure at an exact replay boundary.
#[cfg(test)]
fn inject_fresh_home_cleanup_failure(point: FreshHomeCleanupFailurePoint) {
    FRESH_HOME_CLEANUP_FAILURE.with(|failure| {
        assert!(failure.replace(Some(point)).is_none());
    });
}

// Consumes one exact thread-confined cleanup failure without affecting parallel tests.
#[cfg(test)]
fn take_fresh_home_cleanup_failure(point: FreshHomeCleanupFailurePoint) -> bool {
    FRESH_HOME_CLEANUP_FAILURE.with(|failure| {
        if failure.borrow().as_ref() != Some(&point) {
            return false;
        }
        failure.replace(None);
        true
    })
}

// Retains the validated home descriptor and exact attempt ownership through Core setup.
pub(crate) struct SetupRootPreparation {
    core: Option<File>,
    created_directories: Vec<CreatedSetupDirectory>,
    created_home: Option<CreatedSetupHome>,
    letsinfer_home: File,
    lexical_home: PathBuf,
    owner_user_id: u32,
}

impl SetupRootPreparation {
    // Claims one absent installation home before Core mutation or validates a prior private home.
    pub(crate) fn claim(letsinfer_home: &Path, owner_user_id: u32) -> Result<Self, String> {
        let lexical_home = letsinfer_home.to_path_buf();
        let (parent, name, created_parents) = prepare_home_parent(letsinfer_home, owner_user_id)?;
        let (letsinfer_home, created_home) =
            claim_private_home(parent, name, created_parents, owner_user_id)?;
        Ok(Self {
            core: None,
            created_directories: Vec::new(),
            created_home,
            letsinfer_home,
            lexical_home,
            owner_user_id,
        })
    }

    // Creates or validates the complete installer-owned root closure required by Core setup.
    #[cfg(test)]
    fn prepare(letsinfer_home: &Path, owner_user_id: u32) -> Result<Self, String> {
        let mut preparation = Self::claim(letsinfer_home, owner_user_id)?;
        preparation.complete()?;
        Ok(preparation)
    }

    // Completes the private setup closure only after immutable Core installation succeeds.
    pub(crate) fn complete(&mut self) -> Result<(), String> {
        if self.core.is_some() {
            return Ok(());
        }
        self.core = Some(
            open_private_child_directory(&self.letsinfer_home, "core", self.owner_user_id)?
                .ok_or_else(|| "Core setup immutable root is unavailable".to_string())?,
        );
        for name in ["setup", "material", "configuration"] {
            if let Err(error) = self.prepare_directory(SetupDirectoryParent::Home, name) {
                return match self.rollback_created_directories() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(format!(
                        "{error}; Core setup root rollback failed: {rollback}"
                    )),
                };
            }
        }
        if let Err(error) = self.prepare_directory(SetupDirectoryParent::Core, ".uninstall") {
            return match self.rollback_created_directories() {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!(
                    "{error}; Core setup root rollback failed: {rollback}"
                )),
            };
        }
        Ok(())
    }

    // Creates one absent private directory or validates one exact replayed directory.
    fn prepare_directory(
        &mut self,
        parent: SetupDirectoryParent,
        name: &'static str,
    ) -> Result<(), String> {
        let parent_directory = match parent {
            SetupDirectoryParent::Core => self
                .core
                .as_ref()
                .ok_or_else(|| "Core setup immutable root is unavailable".to_string())?,
            SetupDirectoryParent::Home => &self.letsinfer_home,
        };
        let name_value = contained_setup_name(name)?;
        let PrivateDirectoryClaim::Created {
            device,
            directory,
            inode,
        } = create_private_directory_at(
            parent_directory,
            &name_value,
            self.owner_user_id,
            "root",
            true,
        )?
        else {
            return Ok(());
        };
        drop(directory);
        self.created_directories.push(CreatedSetupDirectory {
            device,
            inode,
            name,
            parent,
        });
        Ok(())
    }

    // Removes only preparation-created directories that remain empty, private, and unchanged.
    #[cfg(test)]
    fn rollback(mut self) -> Result<(), String> {
        self.rollback_created_directories()
    }

    // Removes only empty setup children whose exact identities this preparation created.
    fn rollback_created_directories(&mut self) -> Result<(), String> {
        for directory in self.created_directories.iter().rev() {
            let parent = match directory.parent {
                SetupDirectoryParent::Core => self
                    .core
                    .as_ref()
                    .ok_or_else(|| "Core setup immutable root is unavailable".to_string())?,
                SetupDirectoryParent::Home => &self.letsinfer_home,
            };
            let Some(opened) =
                open_private_child_directory(parent, directory.name, self.owner_user_id)?
            else {
                continue;
            };
            let metadata = opened
                .metadata()
                .map_err(|error| format!("Core setup root metadata is unavailable: {error}"))?;
            if metadata.dev() != directory.device || metadata.ino() != directory.inode {
                return Err(format!(
                    "Core setup root changed during rollback: {}",
                    directory.name
                ));
            }
            drop(opened);
            let name = contained_setup_name(directory.name)?;
            let removed =
                unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
            if removed != 0 {
                let error = std::io::Error::last_os_error();
                if matches!(error.raw_os_error(), Some(code) if code == libc::ENOTEMPTY || code == libc::EEXIST)
                {
                    continue;
                }
                return Err(format!(
                    "Core setup root could not be removed during rollback: {}: {}",
                    directory.name, error
                ));
            }
            parent.sync_all().map_err(|error| {
                format!("Core setup rollback could not be synchronized: {error}")
            })?;
        }
        self.created_directories.clear();
        Ok(())
    }

    // Retires only this attempt's exact fresh home after every public activation is restored.
    pub(crate) fn cleanup_created_home(&mut self) -> Result<(), String> {
        let Some(created) = self.created_home.as_mut() else {
            return Ok(());
        };
        cleanup_created_home(created, self.owner_user_id)?;
        #[cfg(test)]
        if take_fresh_home_cleanup_failure(FreshHomeCleanupFailurePoint::BeforeParentCleanup) {
            return Err("injected Core setup parent cleanup failure".to_string());
        }
        rollback_created_parents(&mut created.created_parents)?;
        self.created_home = None;
        Ok(())
    }

    // Returns the stable owner used by Core setup input and root validation.
    pub(crate) const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Reopens the complete lexical chain and requires the pinned home descriptor identity.
    pub(crate) fn validate_lexical_home(&self, path: &Path) -> Result<(), String> {
        if path != self.lexical_home {
            return Err("Core setup installation home path changed".to_string());
        }
        let observed = open_lexical_directory(path)?;
        validate_private_directory_metadata(&observed, self.owner_user_id)?;
        let expected = self.letsinfer_home.metadata().map_err(|error| {
            format!("Core setup installation home metadata is unavailable: {error}")
        })?;
        let actual = observed.metadata().map_err(|error| {
            format!("Core setup installation home metadata is unavailable: {error}")
        })?;
        if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
            return Err("Core setup installation home lexical identity changed".to_string());
        }
        Ok(())
    }
}

impl SetupSummary {
    // Returns the stable nonempty details presented after successful setup.
    pub fn details(&self) -> Vec<(&str, &str)> {
        let mut values = vec![("Node", self.display_name.as_str())];
        if let Some(endpoint) = &self.inference_endpoint {
            values.push(("API", endpoint.as_str()));
        }
        if let Some(key_file) = &self.api_key_file {
            values.push(("API key", key_file.as_str()));
        }
        values
    }
}

// Owns platform preparation and the exact Core setup process transaction boundary.
pub struct ServiceManager<'a> {
    arguments: &'a InstallerArguments,
    control_address_provider: Arc<dyn ControlAddressProvider>,
    core_setup_process_spawner: Arc<dyn CoreSetupProcessSpawner>,
    resolved_control_address: OnceLock<String>,
}

impl<'a> ServiceManager<'a> {
    // Creates one service lifecycle bound to the requested installation mode.
    pub fn new(arguments: &'a InstallerArguments) -> Self {
        Self {
            arguments,
            control_address_provider: Arc::new(SystemControlAddressProvider),
            core_setup_process_spawner: Arc::new(SystemCoreSetupProcessSpawner),
            resolved_control_address: OnceLock::new(),
        }
    }

    // Acquires system-launcher authority before any native host mutation begins.
    pub fn preflight_privileges(&self, facts: &ProbeFacts) -> Result<(), String> {
        if self.arguments.run_setup {
            self.control_address()?;
        }
        if self.arguments.user_install {
            return Ok(());
        }
        let sudo = required_dependency(facts, "sudo")?;
        run_checked(
            Command::new(sudo).arg("-v"),
            "system installation requires sudo",
        )?;
        Ok(())
    }

    // Prepares platform services required before Core setup may mutate state.
    pub fn prepare(
        &self,
        facts: &ProbeFacts,
        display: &mut DisplayManager,
    ) -> Result<Option<String>, String> {
        if !self.arguments.run_setup || self.arguments.operating_system() != "linux" {
            return Ok(None);
        }
        self.ensure_local_discovery(facts)?;
        self.ensure_docker(facts, display)
    }

    // Establishes exact fresh-home ownership before immutable Core mutates the installation tree.
    pub(crate) fn prepare_setup_root(&self) -> Result<Option<SetupRootPreparation>, String> {
        if !self.arguments.run_setup {
            return Ok(None);
        }
        let owner_user_id = current_user_id(self.arguments)?;
        SetupRootPreparation::claim(&self.arguments.letsinfer_home, owner_user_id).map(Some)
    }

    // Runs Core setup and validates the result committed by its service transaction owner.
    pub fn setup(
        &self,
        facts: &ProbeFacts,
        core: &mut CoreInstallResult,
        docker_group: Option<&str>,
    ) -> Result<Option<SetupSummary>, ServiceSetupError> {
        if !self.arguments.run_setup {
            return Ok(None);
        }
        validate_core_setup_home(core, &self.arguments.letsinfer_home)
            .map_err(ServiceSetupError::recovery_required)?;
        let owner_user_id = core
            .setup_root_preparation
            .as_ref()
            .ok_or_else(|| {
                ServiceSetupError::safe_to_rollback("Core setup root receipt is unavailable")
            })?
            .owner_user_id();
        self.run_setup(facts, core, docker_group, owner_user_id)
            .map(Some)
    }

    // Invokes Core setup after every installer-owned durable root is ready.
    fn run_setup(
        &self,
        facts: &ProbeFacts,
        core: &mut CoreInstallResult,
        docker_group: Option<&str>,
        owner_user_id: u32,
    ) -> Result<SetupSummary, ServiceSetupError> {
        validate_core_setup_home(core, &self.arguments.letsinfer_home)
            .map_err(ServiceSetupError::recovery_required)?;
        // The effective installation UID owns adjacent command/input resolution; destructive
        // rollback never relies on that authority and remains descriptor-relative.
        let command = if let Some(group) = docker_group {
            let sudo = facts.dependency_path("sudo").ok_or_else(|| {
                ServiceSetupError::safe_to_rollback("sudo is required for refreshed Docker access")
            })?;
            let user = command_output(&self.arguments.id_command, &["-un"])
                .map_err(ServiceSetupError::safe_to_rollback)?;
            let mut arguments = ["-u", &user, "-g", group, "env"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>();
            arguments.push(std::ffi::OsString::from(format!(
                "LETSINFER_HOME={}",
                self.arguments.letsinfer_home.display()
            )));
            for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
                if let Some(value) = env::var_os(name) {
                    arguments.push(std::ffi::OsString::from(format!(
                        "{}={}",
                        name,
                        value.to_string_lossy()
                    )));
                }
            }
            arguments.push(core.setup_command.as_os_str().to_owned());
            CoreSetupCommand::new(sudo, arguments)
        } else {
            CoreSetupCommand::new(core.setup_command.clone(), Vec::new())
        };
        let control_address = self
            .control_address()
            .map_err(ServiceSetupError::safe_to_rollback)?;
        let expected_result = expected_setup_result(self.arguments, control_address);
        let input = setup_input(self.arguments, facts, core, owner_user_id, control_address)
            .map_err(ServiceSetupError::safe_to_rollback)?;
        let input = serde_json::to_vec(&input).map_err(|_| {
            ServiceSetupError::safe_to_rollback("Core setup input could not be encoded")
        })?;
        core.setup_root_preparation
            .as_mut()
            .ok_or_else(|| {
                ServiceSetupError::safe_to_rollback("Core setup root receipt is unavailable")
            })?
            .complete()
            .map_err(ServiceSetupError::safe_to_rollback)?;
        let preparation = core.setup_root_preparation.as_ref().ok_or_else(|| {
            ServiceSetupError::safe_to_rollback("Core setup root receipt is unavailable")
        })?;
        let result = run_core_setup_protocol_with_authority(
            self.core_setup_process_spawner.as_ref(),
            preparation,
            &self.arguments.letsinfer_home,
            &command,
            &input,
            &expected_result,
        )
        .map_err(ServiceSetupError::recovery_required)?;
        match result {
            CoreSetupProtocolResult::NotStarted(error) => match core
                .setup_root_preparation
                .as_mut()
                .ok_or_else(|| {
                    ServiceSetupError::safe_to_rollback("Core setup root receipt is unavailable")
                })?
                .rollback_created_directories()
            {
                Ok(()) => Err(ServiceSetupError::safe_to_rollback(error)),
                Err(rollback) => Err(ServiceSetupError::safe_to_rollback(format!(
                    "{error}; Core setup root rollback failed: {rollback}"
                ))),
            },
            CoreSetupProtocolResult::Committed(summary) => {
                core.setup_root_preparation = None;
                Ok(summary)
            }
            CoreSetupProtocolResult::SafeToRollback(error) => {
                Err(ServiceSetupError::safe_to_rollback(error))
            }
            CoreSetupProtocolResult::ReconciliationRequired { reason, .. } => {
                Err(ServiceSetupError::recovery_required(reason))
            }
            CoreSetupProtocolResult::RecoveryRequired(error) => {
                Err(ServiceSetupError::recovery_required(error))
            }
        }
    }

    // Installs or starts local discovery when Linux service setup requires it.
    fn ensure_local_discovery(&self, facts: &ProbeFacts) -> Result<(), String> {
        let systemctl = required_dependency(facts, "systemctl")?;
        if command_success(
            &systemctl,
            &["is-active", "--quiet", "avahi-daemon.service"],
        ) {
            return Ok(());
        }
        let sudo = required_dependency(facts, "sudo")?;
        run_checked(
            Command::new(sudo).args(["systemctl", "enable", "--now", "avahi-daemon.service"]),
            "local discovery service could not start",
        )?;
        if !command_success(
            &systemctl,
            &["is-active", "--quiet", "avahi-daemon.service"],
        ) {
            return Err("local discovery service is unavailable".to_string());
        }
        Ok(())
    }

    // Starts Docker and resolves current-user socket access before Core setup.
    fn ensure_docker(
        &self,
        facts: &ProbeFacts,
        display: &mut DisplayManager,
    ) -> Result<Option<String>, String> {
        let docker = required_dependency(facts, "docker")?;
        if command_success(&docker, &["info"]) {
            return Ok(None);
        }
        let sudo = required_dependency(facts, "sudo")?;
        if !command_success(&sudo, &["docker", "info"]) {
            run_checked(
                Command::new(&sudo).args(["systemctl", "enable", "--now", "docker.service"]),
                "Docker service could not start",
            )?;
        }
        if !command_success(&sudo, &["docker", "info"]) {
            return Err("Docker daemon is unavailable or unhealthy".to_string());
        }
        if !self.arguments.repair_docker_access {
            return Err(
                "Docker access requires approval; rerun with --repair-docker-access".to_string(),
            );
        }
        let stat = required_dependency(facts, "stat")?;
        let group = command_output(&stat, &["-c", "%G", "/var/run/docker.sock"])?;
        if group.is_empty()
            || !group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("Docker socket group identity is invalid".to_string());
        }
        let user = command_output(&self.arguments.id_command, &["-un"])?;
        let description = format!(
            "Docker is healthy, but {} cannot access its socket. Add {} to {}? Membership grants root-equivalent access.",
            user, user, group
        );
        display.notice(&description);
        run_checked(
            Command::new(&sudo).args(["usermod", "-aG", &group, &user]),
            "Docker group enrollment failed",
        )?;
        let user_id = command_output(&self.arguments.id_command, &["-u"])?;
        run_checked(
            Command::new(&sudo).args([
                "systemctl",
                "restart",
                &format!("user@{}.service", user_id),
            ]),
            "user service manager restart failed",
        )?;
        let systemctl = required_dependency(facts, "systemctl")?;
        for _ in 0..10 {
            if command_success(&systemctl, &["--user", "show-environment"]) {
                return Ok(Some(group));
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err("user service manager did not recover after Docker access repair".to_string())
    }

    // Resolves one stable routable address once and retains it across preflight and setup.
    fn control_address(&self) -> Result<&str, String> {
        if let Some(address) = self.resolved_control_address.get() {
            return Ok(address.as_str());
        }
        let resolved = resolve_control_address(
            &self.arguments.control_address,
            self.control_address_provider.as_ref(),
        )?;
        if self.resolved_control_address.set(resolved).is_err() {
            return self
                .resolved_control_address
                .get()
                .map(String::as_str)
                .ok_or_else(|| "control address could not be retained".to_string());
        }
        self.resolved_control_address
            .get()
            .map(String::as_str)
            .ok_or_else(|| "control address could not be retained".to_string())
    }
}

// Reopens the complete setup-home chain against the receipt at every process authority boundary.
fn validate_core_setup_home(core: &CoreInstallResult, home: &Path) -> Result<(), String> {
    core.setup_root_preparation
        .as_ref()
        .ok_or_else(|| "Core setup root receipt is unavailable".to_string())?
        .validate_lexical_home(home)
}

// Runs one setup protocol only while its receipt-bound lexical home remains authoritative.
fn run_core_setup_protocol_with_authority(
    spawner: &dyn CoreSetupProcessSpawner,
    preparation: &SetupRootPreparation,
    home: &Path,
    command: &CoreSetupCommand,
    input: &[u8],
    expected: &ExpectedSetupResult,
) -> Result<CoreSetupProtocolResult, String> {
    let authorized_spawner = AuthorizedCoreSetupProcessSpawner {
        delegate: spawner,
        home,
        preparation,
    };
    let result = run_core_setup_protocol(&authorized_spawner, command, input, expected);
    preparation.validate_lexical_home(home).map_err(|error| {
        format!("Core setup home identity changed across process completion: {error}")
    })?;
    Ok(result)
}

// Runs one setup attempt and at most one exact replay after an ambiguous completed outcome.
fn run_core_setup_protocol(
    spawner: &dyn CoreSetupProcessSpawner,
    command: &CoreSetupCommand,
    input: &[u8],
    expected: &ExpectedSetupResult,
) -> CoreSetupProtocolResult {
    let first = run_core_setup_attempt(spawner, command, input, expected);
    let CoreSetupProtocolResult::ReconciliationRequired {
        committed_seen,
        reason: first_error,
    } = first
    else {
        return first;
    };
    match run_core_setup_attempt(spawner, command, input, expected) {
        CoreSetupProtocolResult::Committed(summary) => CoreSetupProtocolResult::Committed(summary),
        CoreSetupProtocolResult::SafeToRollback(error) if !committed_seen => {
            CoreSetupProtocolResult::SafeToRollback(format!(
                "Core setup exact reconciliation proved rollback-safe: {error}"
            ))
        }
        CoreSetupProtocolResult::SafeToRollback(error) => {
            CoreSetupProtocolResult::RecoveryRequired(format!(
                "Core setup requires recovery after a committed result contradicted exact reconciliation: {first_error}; {error}"
            ))
        }
        CoreSetupProtocolResult::NotStarted(error)
        | CoreSetupProtocolResult::ReconciliationRequired { reason: error, .. }
        | CoreSetupProtocolResult::RecoveryRequired(error) => {
            CoreSetupProtocolResult::RecoveryRequired(format!(
                "Core setup requires recovery after exact reconciliation: {first_error}; {error}"
            ))
        }
    }
}

// Executes one exact machine-protocol attempt while closing stdin and invoking one mandatory wait.
fn run_core_setup_attempt(
    spawner: &dyn CoreSetupProcessSpawner,
    command: &CoreSetupCommand,
    input: &[u8],
    expected: &ExpectedSetupResult,
) -> CoreSetupProtocolResult {
    let mut child = match spawner.spawn(command) {
        Ok(child) => child,
        Err(error) => return CoreSetupProtocolResult::NotStarted(error),
    };
    let input_error = child.write_input(input).err();
    let completion = child.wait();
    if let Some(input_error) = input_error {
        return match completion {
            Ok(output) => match classify_core_setup_output(output, expected) {
                CoreSetupProtocolResult::Committed(summary) => {
                    CoreSetupProtocolResult::Committed(summary)
                }
                CoreSetupProtocolResult::ReconciliationRequired {
                    committed_seen: true,
                    reason,
                } => CoreSetupProtocolResult::ReconciliationRequired {
                    committed_seen: true,
                    reason: format!("{input_error}; {reason}"),
                },
                _ => CoreSetupProtocolResult::ReconciliationRequired {
                    committed_seen: false,
                    reason: input_error,
                },
            },
            Err(wait_error) => {
                CoreSetupProtocolResult::RecoveryRequired(format!("{input_error}; {wait_error}"))
            }
        };
    }
    let output = match completion {
        Ok(output) => output,
        Err(error) => return CoreSetupProtocolResult::RecoveryRequired(error),
    };
    classify_core_setup_output(output, expected)
}

// Classifies only exact machine status after both captured streams satisfy their boundaries.
fn classify_core_setup_output(
    output: CoreSetupProcessOutput,
    expected: &ExpectedSetupResult,
) -> CoreSetupProtocolResult {
    if output.stdout.len() > MAXIMUM_CORE_SETUP_OUTPUT_BYTES
        || output.stderr.len() > MAXIMUM_CORE_SETUP_ERROR_BYTES
    {
        return CoreSetupProtocolResult::ReconciliationRequired {
            committed_seen: output.status == Some(CORE_SETUP_EXIT_COMMITTED),
            reason: "Core setup output exceeded its boundary".to_string(),
        };
    }
    match output.status {
        Some(CORE_SETUP_EXIT_COMMITTED) => match decode_setup_summary(&output.stdout, expected) {
            Ok(summary) => CoreSetupProtocolResult::Committed(summary),
            Err(reason) => CoreSetupProtocolResult::ReconciliationRequired {
                committed_seen: true,
                reason,
            },
        },
        Some(CORE_SETUP_EXIT_SAFE_TO_ROLLBACK) => CoreSetupProtocolResult::SafeToRollback(format!(
            "Core setup failed: {}",
            first_diagnostic(&output.stderr)
        )),
        Some(CORE_SETUP_EXIT_RECOVERY_REQUIRED) => {
            CoreSetupProtocolResult::ReconciliationRequired {
                committed_seen: false,
                reason: format!(
                    "Core setup requires recovery: {}",
                    first_diagnostic(&output.stderr)
                ),
            }
        }
        Some(status) => CoreSetupProtocolResult::ReconciliationRequired {
            committed_seen: false,
            reason: format!(
                "Core setup returned an unknown status {status}: {}",
                first_diagnostic(&output.stderr)
            ),
        },
        None => CoreSetupProtocolResult::ReconciliationRequired {
            committed_seen: false,
            reason: format!(
                "Core setup terminated without a status: {}",
                first_diagnostic(&output.stderr)
            ),
        },
    }
}

// Decodes and validates the closed successful Core document before projecting display fields.
fn decode_setup_summary(
    bytes: &[u8],
    expected: &ExpectedSetupResult,
) -> Result<SetupSummary, String> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CORE_SETUP_OUTPUT_BYTES {
        return Err("Core setup result exceeded its boundary".to_string());
    }
    let result: CoreSetupResultDocument = serde_json::from_slice(bytes)
        .map_err(|error| format!("Core setup result is invalid: {error}"))?;
    let CoreSetupResultDocument {
        schema,
        status,
        node_id,
        machine_id,
        installation_id,
        display_name,
        role,
        control_address,
        api_key_file,
        inference_endpoint,
        services,
    } = result;
    match status {
        CoreSetupResultDisposition::Installed | CoreSetupResultDisposition::Replayed => {}
    }
    if schema.name != CORE_SETUP_RESULT_SCHEMA_NAME
        || schema.version != CORE_SETUP_RESULT_SCHEMA_VERSION
    {
        return Err("Core setup result schema is unsupported".to_string());
    }
    if !is_lower_hex_identity(&node_id, 32) || !is_lower_hex_identity(&machine_id, 32) {
        return Err("Core setup node identity is invalid".to_string());
    }
    if !is_lower_hex_identity(&installation_id, 64) {
        return Err("Core setup installation identity is invalid".to_string());
    }
    if display_name != expected.display_name
        || role != expected.role
        || control_address != expected.control_address
        || api_key_file.0 != expected.api_key_file
        || inference_endpoint.0 != expected.inference_endpoint
        || services != expected.services
    {
        return Err("Core setup result does not match the installation request".to_string());
    }
    Ok(SetupSummary {
        api_key_file: expected.api_key_file.clone(),
        display_name: expected.display_name.clone(),
        inference_endpoint: expected.inference_endpoint.clone(),
        role: expected.role.clone(),
    })
}

// Verifies one canonical lowercase hexadecimal identity of an exact byte length.
fn is_lower_hex_identity(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

// Isolates default-route observation so deterministic tests never inspect the test host.
trait ControlAddressProvider: Send + Sync {
    // Returns the numeric source address selected by the host's default IPv4 route.
    fn default_route_address(&self) -> Result<Ipv4Addr, String>;
}

// Observes the native default route without sending application data.
struct SystemControlAddressProvider;

impl ControlAddressProvider for SystemControlAddressProvider {
    // Returns the source address the kernel selects for one documentation-only destination.
    fn default_route_address(&self) -> Result<Ipv4Addr, String> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(|_| "control address route observation could not start".to_string())?;
        socket
            .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
            .map_err(|_| "a default IPv4 route is unavailable".to_string())?;
        match socket
            .local_addr()
            .map_err(|_| "control address route could not be observed".to_string())?
            .ip()
        {
            IpAddr::V4(address) => Ok(address),
            IpAddr::V6(_) => Err("the default route did not select IPv4".to_string()),
        }
    }
}

// Resolves one explicit or observed address and rejects non-routable listener identities.
fn resolve_control_address(
    selection: &ControlAddressSelection,
    provider: &dyn ControlAddressProvider,
) -> Result<String, String> {
    let address = match selection {
        ControlAddressSelection::Automatic => provider.default_route_address()?.to_string(),
        ControlAddressSelection::Explicit(address) => address.clone(),
    };
    if let Ok(address) = address.parse::<IpAddr>() {
        if !matches!(address, IpAddr::V4(value) if !value.is_loopback() && !value.is_unspecified() && !value.is_multicast())
        {
            return Err("control address must be a routable IPv4 address".to_string());
        }
    }
    Ok(address)
}

// Projects every request-known success value once for initial execution and exact replay.
fn expected_setup_result(
    arguments: &InstallerArguments,
    control_address: &str,
) -> ExpectedSetupResult {
    let services = if arguments.operating_system() == "linux" {
        vec!["li_node", "li_watchdog", "li_gateway"]
    } else {
        vec!["li_node", "li_gateway"]
    };
    ExpectedSetupResult {
        api_key_file: Some(path_text(
            &arguments.letsinfer_home.join("material/trust/api.key"),
        )),
        control_address: control_address.to_string(),
        display_name: SETUP_DISPLAY_NAME.to_string(),
        inference_endpoint: Some(setup_inference_endpoint(control_address)),
        role: SETUP_ROLE.to_string(),
        services: services.into_iter().map(str::to_string).collect(),
    }
}

// Projects the user-facing endpoint from the one submitted public-listener port.
fn setup_inference_endpoint(control_address: &str) -> String {
    format!("http://{control_address}:{SETUP_GATEWAY_PUBLIC_PORT}")
}

// Projects the public listener from one host and port source of truth.
fn setup_gateway_public_address() -> String {
    format!("{SETUP_GATEWAY_PUBLIC_HOST}:{SETUP_GATEWAY_PUBLIC_PORT}")
}

// Projects the private Node listener from one host and port source of truth.
fn setup_node_private_address() -> String {
    format!("{SETUP_NODE_PRIVATE_HOST}:{SETUP_NODE_PRIVATE_PORT}")
}

// Projects the private Gateway listener from one host and port source of truth.
fn setup_gateway_private_address() -> String {
    format!("{SETUP_GATEWAY_PRIVATE_HOST}:{SETUP_GATEWAY_PRIVATE_PORT}")
}

// Projects the Linux Watchdog listener from one loopback host and port source of truth.
fn setup_watchdog_address() -> String {
    format!("{SETUP_WATCHDOG_HOST}:{SETUP_WATCHDOG_PORT}")
}

// Builds the single closed native setup document from the verified release and final probe.
fn setup_input(
    arguments: &InstallerArguments,
    facts: &ProbeFacts,
    core: &CoreInstallResult,
    owner_user_id: u32,
    control_address: &str,
) -> Result<Value, String> {
    let home_directory = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "HOME is unavailable".to_string())?;
    let letsinfer_home = &arguments.letsinfer_home;
    let setup_state = letsinfer_home.join("setup");
    let material = letsinfer_home.join("material");
    let trust_workspace = letsinfer_home.join("trust-workspace");
    let configuration = letsinfer_home.join("configuration");
    let gateway_telemetry_file = material.join("gateway/telemetry.json");
    let path = |relative: &str| path_text(&material.join(relative));
    let linux = arguments.operating_system() == "linux";
    let github_cli_command = linux
        .then(|| required_dependency(facts, "gh"))
        .transpose()?;
    let request_id = setup_request_identity(arguments, core, control_address);
    let watchdog_material = linux.then(|| {
        json!({
            "authority_private_key_file": path("trust/watchdog-ca.key"),
            "authority_certificate_file": path("trust/watchdog-ca.crt"),
            "server_certificate_file": path("trust/watchdog-server.crt"),
            "server_private_key_file": path("trust/watchdog-server.key"),
            "controller_certificate_file": path("trust/watchdog-controller.crt"),
            "controller_private_key_file": path("trust/watchdog-controller.key"),
            "controller_allowlist_file": path("trust/watchdog-controllers.allow")
        })
    });
    let watchdog_configuration = linux.then(|| {
        json!({
            "data_directory": path_text(&material.join("watchdog")),
            "controller_snapshot_path": path("watchdog/controller-snapshot.json"),
            "site_state_path": path("watchdog/site-state.json"),
            "gateway_metrics_path": path_text(&gateway_telemetry_file),
            "protection_root_path": path_text(&watchdog_protection_root(&material)),
            "runtime_installation_root": path_text(&letsinfer_home.join("runtimes")),
            "runtime_cache_root": path_text(&letsinfer_home.join("cache")),
            "flush_interval_milliseconds": 5000,
            "maximum_controllers": 8,
            "thresholds": {
                "warning_available_bytes": 3000000000_u64,
                "graceful_available_bytes": 2000000000_u64,
                "emergency_available_bytes": 1000000000_u64,
                "swap_stop_bytes": 1000000_u64,
                "psi_some_microseconds": 100000_u64,
                "psi_full_microseconds": 10000_u64,
                "state_failures": 3,
                "containment_grace_milliseconds": 5000
            }
        })
    });
    let benchmark_configuration = linux.then(|| {
        json!({
            "worker_executable": path_text(&core.installation_root.join("bin/li_benchmark_worker")),
            "github_cli_command": path_text(github_cli_command.as_ref().expect("Linux dependency")),
            "task_root": path_text(&letsinfer_home.join("benchmark_tasks")),
            "telemetry_root": path_text(&letsinfer_home.join("benchmark_telemetry")),
            "evidence_root": path_text(&letsinfer_home.join("benchmark_evidence")),
            "signing_workspace_root": path_text(&letsinfer_home.join("benchmark_signing")),
            "maximum_runtime_milliseconds": 604800000_u64,
            "stop_grace_milliseconds": 30000,
            "watchdog_timeout_milliseconds": 5000
        })
    });
    let model = setup_model(arguments, facts, &home_directory)?;
    let hardware = setup_hardware(arguments, facts, core)?;
    let pairing = setup_pairing(arguments.operating_system(), facts)?;
    let placement_safety = setup_placement_safety(arguments, core)?;
    let native = setup_native(arguments, facts, &path)?;
    let supervisor_command = if linux {
        required_dependency(facts, "systemctl")?
    } else {
        required_dependency(facts, "launchctl")?
    };
    let ssh_keygen_command = required_dependency(facts, "ssh_keygen")?;
    let launcher_file = arguments.launcher_root.join("letsinfer");
    let privilege_command = if arguments.user_install {
        None
    } else {
        Some(required_dependency(facts, "sudo")?)
    };
    let release_platform = arguments.selected_platform.replace('-', "_");
    Ok(json!({
        "schema": {"name": "li_core_setup_input", "version": 5},
        "owner_user_id": owner_user_id,
        "request": {
            "request_id": request_id,
            "platform": arguments.operating_system(),
            "role": SETUP_ROLE,
            "core_version": core.version,
            "core_source_identity": core.source_identity,
            "display_name": SETUP_DISPLAY_NAME,
            "control_address": control_address,
            "node_private_address": setup_node_private_address(),
            "gateway_private_address": setup_gateway_private_address(),
            "gateway_public_address": setup_gateway_public_address(),
            "watchdog_address": linux.then(setup_watchdog_address)
        },
        "roots": {
            "letsinfer_home": path_text(letsinfer_home),
            "home_directory": path_text(&home_directory),
            "setup_state_directory": path_text(&setup_state),
            "material_root": path_text(&material),
            "trust_workspace_root": path_text(&trust_workspace),
            "configuration_directory": path_text(&configuration)
        },
        "material": {
            "database_file": path("state/li_core.sqlite3"),
            "pairing_setup_secret_file": path("trust/pairing.key"),
            "api_key_file": path("trust/api.key"),
            "benchmark_signing": {
                "private_key_file": path("trust/benchmark-signing.key"),
                "public_key_file": path("trust/benchmark-signing.pub")
            },
            "pairing": {
                "site_private_key_file": path("trust/site.key"),
                "site_public_key_file": path("trust/site.pub"),
                "site_ca_certificate_file": path("trust/site-ca.crt"),
                "local_control_certificate_file": path("trust/local-control.crt")
            },
            "node": mutual_tls_material(&path, "node"),
            "gateway": gateway_material(&path),
            "watchdog": watchdog_material
        },
        "configuration": {
            "provider_identity": core.source_identity,
            "cli": {
                "entropy_source": "/dev/urandom",
                "launcher_file": path_text(&launcher_file),
                "privilege_command": privilege_command.as_ref().map(|path| path_text(path)),
                "timeout_milliseconds": 5000,
                "maximum_response_bytes": 1048576
            },
            "node": {
                "core_update": {
                    "release_platform": release_platform,
                    "letsinfer_home": path_text(letsinfer_home),
                    "home_directory": path_text(&home_directory),
                    "setup_state_directory": path_text(&setup_state),
                    "configuration_root": path_text(&configuration),
                    "curl_command": path_text(&arguments.curl_command),
                    "ssh_keygen_command": path_text(&ssh_keygen_command),
                    "allowed_signers_file": path_text(&letsinfer_home.join("trust/release-allowed-signers")),
                    "supervisor_command": path_text(&supervisor_command),
                    "readiness_timeout_milliseconds": 30000,
                    "readiness_poll_milliseconds": 100,
                    "stable_readiness_observations": 2
                },
                "model": model,
                "benchmark": benchmark_configuration,
                "hardware": hardware,
                "pairing": pairing,
                "placement_safety": placement_safety,
                "trust_workspace": path_text(&pairing_trust_workspace(&trust_workspace)),
                "daemon_cadence_milliseconds": 1000,
                "local_api": local_api(&configuration.join("li_node.sock")),
                "remote_maximum_workers": 16,
                "remote_accept_poll_interval_milliseconds": 100,
                "remote_handshake_timeout_milliseconds": 5000,
                "remote_read_timeout_milliseconds": 5000,
                "remote_write_timeout_milliseconds": 5000
            },
            "gateway": {
                "health": local_api(&configuration.join("li_gateway_health.sock")),
                "node_protection": {
                    "socket_path": path_text(&configuration.join("li_node_protection.sock")),
                    "read_timeout_milliseconds": 1000,
                    "write_timeout_milliseconds": 1000,
                    "maximum_cache_milliseconds": 3000,
                    "poll_interval_milliseconds": 1000
                },
                "telemetry_file": path_text(&gateway_telemetry_file),
                "telemetry_cadence_milliseconds": 1000,
                "maximum_queue_milliseconds": 30000,
                "public_maximum_connections": 64,
                "private_maximum_connections": 32
            },
            "watchdog": watchdog_configuration
        },
        "native": native
    }))
}

// Returns the exact shared Node and Watchdog protection root required by both providers.
fn watchdog_protection_root(material_root: &Path) -> PathBuf {
    material_root
        .join("watchdog")
        .join(WATCHDOG_PROTECTION_ROOT_NAME)
}

// Returns the exact ephemeral trust workspace accepted by the pairing provider.
fn pairing_trust_workspace(trust_workspace_root: &Path) -> PathBuf {
    trust_workspace_root.join(PAIRING_TRUST_WORKSPACE_NAME)
}

// Resolves the exact effective installation owner once before root preparation and setup input.
fn current_user_id(arguments: &InstallerArguments) -> Result<u32, String> {
    command_output(&arguments.id_command, &["-u"])?
        .parse::<u32>()
        .map_err(|_| "current user identity is invalid".to_string())
}

// Encodes one fixed installer-owned direct-child name for descriptor-relative operations.
fn contained_setup_name(name: &str) -> Result<CString, String> {
    if !matches!(
        name,
        "core" | "setup" | "material" | "configuration" | ".uninstall"
    ) {
        return Err("Core setup root name is invalid".to_string());
    }
    CString::new(name).map_err(|_| "Core setup root name is invalid".to_string())
}

// Opens or creates every nonsymlink parent component and returns the final contained home name.
fn prepare_home_parent(
    path: &Path,
    owner_user_id: u32,
) -> Result<(File, CString, Vec<CreatedSetupParent>), String> {
    let components = strict_absolute_path_components(path)?;
    let (name, parent_components) = components
        .split_last()
        .ok_or_else(|| "Core setup installation home name is unavailable".to_string())?;
    let name = contained_path_name(name)?;
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| format!("Core setup installation root is unavailable: {error}"))?;
    let mut created_parents = Vec::new();
    for component in parent_components {
        let component = contained_path_name(component)?;
        match create_private_directory_at(
            &parent,
            &component,
            owner_user_id,
            "installation home parent",
            false,
        ) {
            Ok(PrivateDirectoryClaim::Existing(directory)) => parent = directory,
            Ok(PrivateDirectoryClaim::Created {
                device,
                directory,
                inode,
            }) => {
                created_parents.push(CreatedSetupParent {
                    device,
                    inode,
                    name: component,
                    parent,
                });
                parent = directory;
            }
            Err(error) => {
                return Err(rollback_created_parents_after_error(
                    &mut created_parents,
                    error,
                ))
            }
        }
    }
    Ok((parent, name, created_parents))
}

// Opens one complete absolute directory chain without following any lexical symlink component.
fn open_lexical_directory(path: &Path) -> Result<File, String> {
    let components = strict_absolute_path_components(path)?;
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| format!("Core setup installation root is unavailable: {error}"))?;
    for component in components {
        let name = contained_path_name(component)?;
        directory = open_directory_at(&directory, &name)?
            .ok_or_else(|| "Core setup installation home disappeared".to_string())?;
    }
    Ok(directory)
}

// Accepts exactly one leading root followed only by ordinary nonempty native components.
fn strict_absolute_path_components(path: &Path) -> Result<Vec<&OsStr>, String> {
    let bytes = path.as_os_str().as_bytes();
    if !bytes.starts_with(b"/") || bytes.len() == 1 {
        return Err("Core setup installation home is invalid".to_string());
    }
    let mut values = Vec::new();
    for component in bytes[1..].split(|value| *value == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err("Core setup installation home contains an alias".to_string());
        }
        values.push(OsStr::from_bytes(component));
    }
    Ok(values)
}

// Creates or opens one exact private child without changing process-global creation policy.
fn create_private_directory_at(
    parent: &File,
    name: &CStr,
    owner_user_id: u32,
    label: &str,
    require_private_existing: bool,
) -> Result<PrivateDirectoryClaim, String> {
    let umask = PrivateDirectoryUmaskGuard::acquire()?;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    drop(umask);
    if created != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("Core setup {label} could not be created: {error}"));
        }
        let directory = open_directory_at(parent, name)?
            .ok_or_else(|| format!("Core setup {label} disappeared"))?;
        if require_private_existing {
            validate_private_directory_metadata(&directory, owner_user_id)?;
        }
        return Ok(PrivateDirectoryClaim::Existing(directory));
    }
    #[cfg(test)]
    if take_private_directory_failure(label, PrivateDirectoryFailurePoint::BeforeOpen) {
        return Err(rollback_exclusive_created_entry(
            parent,
            name,
            owner_user_id,
            label,
            format!("injected Core setup {label} open failure"),
        ));
    }
    let directory = match open_directory_at(parent, name) {
        Ok(Some(directory)) => directory,
        Ok(None) => {
            return Err(rollback_exclusive_created_entry(
                parent,
                name,
                owner_user_id,
                label,
                format!("Core setup {label} disappeared before ownership capture"),
            ))
        }
        Err(error) => {
            return Err(rollback_exclusive_created_entry(
                parent,
                name,
                owner_user_id,
                label,
                format!("{error}; Core setup {label} ownership could not be opened"),
            ))
        }
    };
    #[cfg(test)]
    if take_private_directory_failure(label, PrivateDirectoryFailurePoint::BeforeMetadata) {
        return Err(rollback_exclusive_created_entry(
            parent,
            name,
            owner_user_id,
            label,
            format!("injected Core setup {label} metadata failure"),
        ));
    }
    let identity = match directory.metadata() {
        Ok(identity) => identity,
        Err(error) => {
            return Err(rollback_exclusive_created_entry(
                parent,
                name,
                owner_user_id,
                label,
                format!("Core setup {label} ownership could not be captured: {error}"),
            ))
        }
    };
    if !identity.is_dir() || identity.uid() != owner_user_id {
        return Err(rollback_created_directory_after_error(
            parent,
            name,
            identity.dev(),
            identity.ino(),
            label,
            format!("Core setup {label} identity is unsafe"),
        ));
    }
    #[cfg(test)]
    if take_private_directory_failure(label, PrivateDirectoryFailurePoint::AfterCreate) {
        return Err(rollback_created_directory_after_error(
            parent,
            name,
            identity.dev(),
            identity.ino(),
            label,
            format!("injected Core setup {label} post-create failure"),
        ));
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(rollback_created_directory_after_error(
            parent,
            name,
            identity.dev(),
            identity.ino(),
            label,
            format!(
                "Core setup {label} mode could not be fixed: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    #[cfg(test)]
    if take_private_directory_failure(label, PrivateDirectoryFailurePoint::AfterOpen) {
        return Err(rollback_created_directory_after_error(
            parent,
            name,
            identity.dev(),
            identity.ino(),
            label,
            format!("injected Core setup {label} post-open failure"),
        ));
    }
    let completed = (|| {
        validate_private_directory_metadata(&directory, owner_user_id)?;
        let metadata = directory
            .metadata()
            .map_err(|error| format!("Core setup {label} metadata is unavailable: {error}"))?;
        if metadata.dev() != identity.dev() || metadata.ino() != identity.ino() {
            return Err(format!(
                "Core setup {label} identity changed after creation"
            ));
        }
        #[cfg(test)]
        if take_private_directory_failure(label, PrivateDirectoryFailurePoint::BeforeSync) {
            return Err(format!("injected Core setup {label} pre-sync failure"));
        }
        directory
            .sync_all()
            .map_err(|error| format!("Core setup {label} could not be synchronized: {error}"))?;
        parent
            .sync_all()
            .map_err(|error| format!("Core setup {label} could not be synchronized: {error}"))?;
        Ok(())
    })();
    if let Err(error) = completed {
        return Err(rollback_created_directory_after_error(
            parent,
            name,
            identity.dev(),
            identity.ino(),
            label,
            error,
        ));
    }
    Ok(PrivateDirectoryClaim::Created {
        device: identity.dev(),
        directory,
        inode: identity.ino(),
    })
}

// Compensates one exclusive mkdir before descriptor identity capture using two no-follow checks.
fn rollback_exclusive_created_entry(
    parent: &File,
    name: &CStr,
    owner_user_id: u32,
    label: &str,
    error: String,
) -> String {
    let observed = match metadata_at_optional(parent, name) {
        Ok(None) => return error,
        Ok(Some(observed)) => observed,
        Err(rollback) => return format!("{error}; {rollback}"),
    };
    if observed.st_mode & libc::S_IFMT != libc::S_IFDIR || observed.st_uid != owner_user_id {
        return format!("{error}; Core setup {label} rollback refused an unsafe replacement");
    }
    rollback_created_directory_after_error(
        parent,
        name,
        observed.st_dev as u64,
        observed.st_ino as u64,
        label,
        error,
    )
}

// Removes one exact newly created empty directory and preserves the original creation failure.
fn rollback_created_directory_after_error(
    parent: &File,
    name: &CStr,
    device: u64,
    inode: u64,
    label: &str,
    error: String,
) -> String {
    match remove_created_empty_directory(parent, name, device, inode, label) {
        Ok(()) => error,
        Err(rollback) => format!("{error}; {rollback}"),
    }
}

// Removes one exact empty directory identity reached only through its retained parent descriptor.
fn remove_created_empty_directory(
    parent: &File,
    name: &CStr,
    device: u64,
    inode: u64,
    label: &str,
) -> Result<(), String> {
    let Some(observed) = metadata_at_optional(parent, name)? else {
        return Ok(());
    };
    if observed.st_dev as u64 != device
        || observed.st_ino as u64 != inode
        || observed.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(format!("Core setup {label} changed before rollback"));
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(format!(
            "Core setup {label} rollback failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    parent
        .sync_all()
        .map_err(|error| format!("Core setup {label} rollback could not be synchronized: {error}"))
}

// Exclusively creates one fresh private home or validates one exact pre-existing home.
fn claim_private_home(
    parent: File,
    name: CString,
    mut created_parents: Vec<CreatedSetupParent>,
    owner_user_id: u32,
) -> Result<(File, Option<CreatedSetupHome>), String> {
    let claim =
        match create_private_directory_at(&parent, &name, owner_user_id, "installation home", true)
        {
            Ok(claim) => claim,
            Err(error) => {
                return Err(rollback_created_parents_after_error(
                    &mut created_parents,
                    error,
                ))
            }
        };
    let (directory, device, inode) = match claim {
        PrivateDirectoryClaim::Existing(directory) => return Ok((directory, None)),
        PrivateDirectoryClaim::Created {
            device,
            directory,
            inode,
        } => (directory, device, inode),
    };
    let created_home = CreatedSetupHome {
        created_parents,
        device,
        inode,
        name,
        parent,
        phase: CreatedSetupHomePhase::Claimed,
        quarantine: None,
    };
    Ok((directory, Some(created_home)))
}

// Removes every empty home ancestor created by this attempt from deepest to shallowest.
fn rollback_created_parents(created: &mut Vec<CreatedSetupParent>) -> Result<(), String> {
    while let Some(parent) = created.last() {
        remove_created_empty_directory(
            &parent.parent,
            &parent.name,
            parent.device,
            parent.inode,
            "installation home parent",
        )?;
        created.pop();
    }
    Ok(())
}

// Compensates every already-owned home ancestor without hiding the initiating failure.
fn rollback_created_parents_after_error(
    created: &mut Vec<CreatedSetupParent>,
    error: String,
) -> String {
    match rollback_created_parents(created) {
        Ok(()) => error,
        Err(rollback) => format!("{error}; {rollback}"),
    }
}

// Atomically quarantines and descriptor-relatively removes one exact fresh installation home.
fn cleanup_created_home(created: &mut CreatedSetupHome, owner_user_id: u32) -> Result<(), String> {
    let quarantined_name = CString::new("home").expect("static quarantine child name");
    loop {
        match created.phase {
            CreatedSetupHomePhase::Claimed => {
                require_directory_identity(
                    &created.parent,
                    &created.name,
                    created.device,
                    created.inode,
                    owner_user_id,
                    "installation home",
                )?;
                let (name, directory, device, inode) =
                    create_home_quarantine(&created.parent, owner_user_id)?;
                if let Err(error) = require_directory_identity(
                    &created.parent,
                    &created.name,
                    created.device,
                    created.inode,
                    owner_user_id,
                    "installation home",
                ) {
                    remove_empty_quarantine(&created.parent, &name, device, inode, owner_user_id)?;
                    return Err(error);
                }
                let renamed = unsafe {
                    libc::renameat(
                        created.parent.as_raw_fd(),
                        created.name.as_ptr(),
                        directory.as_raw_fd(),
                        quarantined_name.as_ptr(),
                    )
                };
                if renamed != 0 {
                    let error = std::io::Error::last_os_error();
                    remove_empty_quarantine(&created.parent, &name, device, inode, owner_user_id)?;
                    return Err(format!(
                        "Core setup installation home could not be quarantined: {error}"
                    ));
                }
                created.quarantine = Some(CreatedHomeQuarantine {
                    device,
                    directory,
                    inode,
                    name,
                });
                created.phase = CreatedSetupHomePhase::Quarantined;
                #[cfg(test)]
                if take_fresh_home_cleanup_failure(FreshHomeCleanupFailurePoint::AfterRename) {
                    return Err("injected Core setup post-rename failure".to_string());
                }
            }
            CreatedSetupHomePhase::Quarantined => {
                let quarantine = created.quarantine.as_ref().ok_or_else(|| {
                    "Core setup home quarantine receipt is unavailable".to_string()
                })?;
                created.parent.sync_all().map_err(|error| {
                    format!("Core setup home quarantine could not be synchronized: {error}")
                })?;
                quarantine.directory.sync_all().map_err(|error| {
                    format!("Core setup home quarantine could not be synchronized: {error}")
                })?;
                let quarantined = require_directory_identity(
                    &quarantine.directory,
                    &quarantined_name,
                    created.device,
                    created.inode,
                    owner_user_id,
                    "quarantined installation home",
                )?;
                #[cfg(test)]
                if take_fresh_home_cleanup_failure(FreshHomeCleanupFailurePoint::DuringTraversal) {
                    return Err("injected Core setup traversal failure".to_string());
                }
                remove_directory_contents(&quarantined, created.device, owner_user_id)?;
                if unsafe {
                    libc::unlinkat(
                        quarantine.directory.as_raw_fd(),
                        quarantined_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                } != 0
                {
                    return Err(format!(
                        "Core setup quarantined home could not be removed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                created.phase = CreatedSetupHomePhase::HomeRemoved;
                #[cfg(test)]
                if take_fresh_home_cleanup_failure(FreshHomeCleanupFailurePoint::AfterHomeUnlink) {
                    return Err("injected Core setup post-home-unlink failure".to_string());
                }
            }
            CreatedSetupHomePhase::HomeRemoved => {
                let quarantine = created.quarantine.as_ref().ok_or_else(|| {
                    "Core setup home quarantine receipt is unavailable".to_string()
                })?;
                quarantine.directory.sync_all().map_err(|error| {
                    format!("Core setup home quarantine could not be synchronized: {error}")
                })?;
                remove_empty_quarantine_entry(
                    &created.parent,
                    &quarantine.name,
                    quarantine.device,
                    quarantine.inode,
                    owner_user_id,
                )?;
                created.quarantine = None;
                created.phase = CreatedSetupHomePhase::QuarantineRemoved;
            }
            CreatedSetupHomePhase::QuarantineRemoved => {
                created.parent.sync_all().map_err(|error| {
                    format!("Core setup home quarantine could not be synchronized: {error}")
                })?;
                created.phase = CreatedSetupHomePhase::HomeRetired;
            }
            CreatedSetupHomePhase::HomeRetired => return Ok(()),
        }
    }
}

// Creates one exclusive private sibling that contains only the attempt-owned home during removal.
fn create_home_quarantine(
    parent: &File,
    owner_user_id: u32,
) -> Result<(CString, File, u64, u64), String> {
    for _ in 0..HOME_QUARANTINE_ATTEMPTS {
        let sequence = HOME_QUARANTINE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(
            ".li_installer_home_rollback_{}_{}",
            std::process::id(),
            sequence
        ))
        .map_err(|_| "Core setup home quarantine name is invalid".to_string())?;
        match create_private_directory_at(parent, &name, owner_user_id, "home quarantine", true)? {
            PrivateDirectoryClaim::Existing(_) => continue,
            PrivateDirectoryClaim::Created {
                device,
                directory,
                inode,
            } => return Ok((name, directory, device, inode)),
        }
    }
    Err("Core setup home quarantine name is unavailable".to_string())
}

// Removes one still-empty quarantine only while its parent entry retains the captured identity.
fn remove_empty_quarantine(
    parent: &File,
    name: &CStr,
    device: u64,
    inode: u64,
    owner_user_id: u32,
) -> Result<(), String> {
    remove_empty_quarantine_entry(parent, name, device, inode, owner_user_id)?;
    parent
        .sync_all()
        .map_err(|error| format!("Core setup home quarantine could not be synchronized: {error}"))
}

// Unlinks one exact empty quarantine while deferring parent publication to the receipt phase.
fn remove_empty_quarantine_entry(
    parent: &File,
    name: &CStr,
    device: u64,
    inode: u64,
    owner_user_id: u32,
) -> Result<(), String> {
    drop(require_directory_identity(
        parent,
        name,
        device,
        inode,
        owner_user_id,
        "home quarantine",
    )?);
    let removed = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if removed != 0 {
        return Err(format!(
            "Core setup home quarantine could not be removed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// Reopens one direct child without following it and requires the captured private identity.
fn require_directory_identity(
    parent: &File,
    name: &CStr,
    device: u64,
    inode: u64,
    owner_user_id: u32,
    label: &str,
) -> Result<File, String> {
    let directory = open_directory_at(parent, name)?
        .ok_or_else(|| format!("Core setup {label} disappeared"))?;
    validate_private_directory_metadata(&directory, owner_user_id)?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Core setup {label} metadata is unavailable: {error}"))?;
    if metadata.dev() != device || metadata.ino() != inode {
        return Err(format!("Core setup {label} changed before rollback"));
    }
    Ok(directory)
}

// Recursively unlinks only entries reached beneath one already-opened attempt-owned directory.
fn remove_directory_contents(
    directory: &File,
    expected_device: u64,
    owner_user_id: u32,
) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| {
        format!("Core setup cleanup directory metadata is unavailable: {error}")
    })?;
    if metadata.dev() != expected_device || metadata.uid() != owner_user_id {
        return Err("Core setup cleanup directory ownership is unsafe".to_string());
    }
    let mode = unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) };
    if mode != 0 {
        return Err(format!(
            "Core setup cleanup directory could not be made private: {}",
            std::io::Error::last_os_error()
        ));
    }
    for name in directory_entry_names(directory)? {
        let before = metadata_at(directory, &name)?;
        if before.st_dev as u64 != expected_device {
            return Err("Core setup cleanup cannot cross a filesystem boundary".to_string());
        }
        if before.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = open_directory_at(directory, &name)?
                .ok_or_else(|| "Core setup cleanup directory disappeared".to_string())?;
            let opened = child
                .metadata()
                .map_err(|error| format!("Core setup cleanup metadata is unavailable: {error}"))?;
            if opened.dev() != before.st_dev as u64 || opened.ino() != before.st_ino as u64 {
                return Err("Core setup cleanup directory changed".to_string());
            }
            remove_directory_contents(&child, expected_device, owner_user_id)?;
            require_entry_identity(directory, &name, &before)?;
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(format!(
                    "Core setup cleanup directory could not be removed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        } else {
            require_entry_identity(directory, &name, &before)?;
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(format!(
                    "Core setup cleanup entry could not be removed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    directory
        .sync_all()
        .map_err(|error| format!("Core setup cleanup directory could not be synchronized: {error}"))
}

// Enumerates one descriptor-owned directory without resolving any path from the process root.
fn directory_entry_names(directory: &File) -> Result<Vec<CString>, String> {
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err("Core setup cleanup directory could not be duplicated".to_string());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err("Core setup cleanup directory could not be enumerated".to_string());
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        names.push(
            CString::new(name.to_bytes())
                .map_err(|_| "Core setup cleanup entry name is invalid".to_string())?,
        );
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err("Core setup cleanup directory could not be closed".to_string());
    }
    Ok(names)
}

// Returns one direct child's no-follow native metadata.
fn metadata_at(directory: &File, name: &CStr) -> Result<libc::stat, String> {
    metadata_at_optional(directory, name)?
        .ok_or_else(|| "Core setup cleanup entry disappeared".to_string())
}

// Returns optional no-follow metadata so compensated directory removal remains replay-safe.
fn metadata_at_optional(directory: &File, name: &CStr) -> Result<Option<libc::stat>, String> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!(
            "Core setup cleanup entry metadata is unavailable: {error}"
        ));
    }
    Ok(Some(metadata))
}

// Requires a direct child to retain the exact no-follow identity observed before mutation.
fn require_entry_identity(
    directory: &File,
    name: &CStr,
    expected: &libc::stat,
) -> Result<(), String> {
    let observed = metadata_at(directory, name)?;
    if observed.st_dev != expected.st_dev
        || observed.st_ino != expected.st_ino
        || observed.st_mode & libc::S_IFMT != expected.st_mode & libc::S_IFMT
    {
        return Err("Core setup cleanup entry changed before removal".to_string());
    }
    Ok(())
}

// Opens one exact direct child directory through a retained parent without following a symlink.
fn open_directory_at(parent: &File, name: &CStr) -> Result<Option<File>, String> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("Core setup directory metadata is unsafe: {error}"));
    }
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

// Encodes one single native path component for descriptor-relative mutation.
fn contained_path_name(name: &OsStr) -> Result<CString, String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err("Core setup path component is invalid".to_string());
    }
    CString::new(bytes).map_err(|_| "Core setup path component is invalid".to_string())
}

// Opens and validates the private installation home without following its final component.
#[cfg(test)]
fn open_private_directory(path: &Path, owner_user_id: u32) -> Result<File, String> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "Core setup installation home is unavailable: {}: {}",
                path.display(),
                error
            )
        })?;
    validate_private_directory_metadata(&directory, owner_user_id)?;
    Ok(directory)
}

// Opens one existing private direct child without following a replaced leaf.
fn open_private_child_directory(
    parent: &File,
    name: &str,
    owner_user_id: u32,
) -> Result<Option<File>, String> {
    let name = contained_setup_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("Core setup root metadata is unsafe: {error}"));
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    validate_private_directory_metadata(&directory, owner_user_id)?;
    Ok(Some(directory))
}

// Applies the exact directory type, effective owner, and special-bit-free mode contract.
fn validate_private_directory_metadata(directory: &File, owner_user_id: u32) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("Core setup root metadata is unavailable: {error}"))?;
    if !metadata.is_dir() || metadata.uid() != owner_user_id || metadata.mode() & 0o7777 != 0o700 {
        return Err("Core setup root metadata is unsafe".to_string());
    }
    Ok(())
}

// Builds the exact platform safety authority and immutable Linux peer identities.
fn setup_placement_safety(
    arguments: &InstallerArguments,
    core: &CoreInstallResult,
) -> Result<Value, String> {
    if arguments.operating_system() != "linux" {
        return Ok(json!({"platform": "macos"}));
    }
    let gateway = core.installation_root.join("bin/li_gateway");
    let watchdog = core.installation_root.join("bin/li_watchdog");
    Ok(json!({
        "platform": "linux",
        "maximum_workers": 8,
        "read_timeout_milliseconds": 1000,
        "write_timeout_milliseconds": 1000,
        "accept_poll_interval_milliseconds": 50,
        "gateway": {
            "path": path_text(&gateway),
            "executable_sha256": file_sha256(&gateway)?,
            "principal_id": protection_principal(&core.source_identity, "gateway")
        },
        "watchdog": {
            "path": path_text(&watchdog),
            "executable_sha256": file_sha256(&watchdog)?,
            "principal_id": protection_principal(&core.source_identity, "watchdog")
        },
        "lease_milliseconds": 3000
    }))
}

// Builds every explicit production ModelCoordinator path, command, and bounded allocator input.
fn setup_model(
    arguments: &InstallerArguments,
    facts: &ProbeFacts,
    home_directory: &Path,
) -> Result<Value, String> {
    let letsinfer_home = &arguments.letsinfer_home;
    let linux = arguments.operating_system() == "linux";
    let docker_command = if linux {
        required_dependency(facts, "docker")?
    } else {
        facts
            .dependency_path("docker")
            .unwrap_or_else(|| PathBuf::from("/usr/bin/false"))
    };
    let group_id = command_output(&arguments.id_command, &["-g"])?
        .parse::<u32>()
        .map_err(|_| "current group identity is invalid".to_string())?;
    let launch_agents_root =
        (!linux).then(|| path_text(&home_directory.join("Library/LaunchAgents")));
    let launchctl_command = if linux {
        None
    } else {
        Some(path_text(&required_dependency(facts, "launchctl")?))
    };
    Ok(json!({
        "catalog_source": RUNTIME_CATALOG_SOURCE,
        "catalog_cache_root": path_text(&letsinfer_home.join("catalog-cache")),
        "catalog_hydration_root": path_text(&letsinfer_home.join("catalog-hydration")),
        "http_workspace_root": path_text(&letsinfer_home.join("http-workspace")),
        "installation_root": path_text(&letsinfer_home.join("runtimes")),
        "runtime_cache_root": path_text(&letsinfer_home.join("cache")),
        "curl_command": path_text(&required_dependency(facts, "curl")?),
        "docker_command": path_text(&docker_command),
        "command_working_directory": path_text(&letsinfer_home.join("command-workspace")),
        "placement_material_root": path_text(&letsinfer_home.join("placement_material")),
        "placement_secret_root": path_text(&letsinfer_home.join("placement_secrets")),
        "placement_tls_workspace_root": path_text(&letsinfer_home.join("placement_tls_staging")),
        "first_port": 18000,
        "port_count": 32,
        "endpoint_timeout_milliseconds": 30000,
        "maximum_hardware_age_milliseconds": 60000,
        "group_id": group_id,
        "launch_agents_root": launch_agents_root,
        "launchctl_command": launchctl_command
    }))
}

// Builds the platform-exact hardware provider projection without rediscovering probe facts.
fn setup_hardware(
    arguments: &InstallerArguments,
    facts: &ProbeFacts,
    core: &CoreInstallResult,
) -> Result<Value, String> {
    if arguments.operating_system() == "linux" {
        Ok(json!({
            "platform": "linux",
            "architecture": arguments.architecture(),
            "boot_id_file": "/proc/sys/kernel/random/boot_id",
            "cpu_information_file": "/proc/cpuinfo",
            "memory_information_file": "/proc/meminfo",
            "nvidia_smi_command": optional_dependency(facts, "nvidia_smi"),
            "rdma_command": command_path_if_available("rdma").map(|path| path_text(&path))
        }))
    } else {
        Ok(json!({
            "platform": "macos",
            "sysctl_command": path_text(&required_dependency(facts, "sysctl")?),
            "metal_probe_command": path_text(&core.installation_root.join("bin/li_hardware_macos_probe"))
        }))
    }
}

// Builds the platform-exact pairing discovery and direct-link provider projection.
fn setup_pairing(operating_system: &str, facts: &ProbeFacts) -> Result<Value, String> {
    if operating_system == "linux" {
        setup_linux_pairing(facts, &required_command_path("ip")?)
    } else {
        Ok(json!({
            "platform": "macos",
            "discovery_command": path_text(&required_command_path("dns-sd")?)
        }))
    }
}

// Builds Linux pairing input from the observed publisher and explicit direct-link command.
fn setup_linux_pairing(facts: &ProbeFacts, direct_link_ip_command: &Path) -> Result<Value, String> {
    Ok(json!({
        "platform": "linux",
        "discovery_command": path_text(&required_dependency(facts, "avahi_publish_service")?),
        "direct_link_sys_class": "/sys/class",
        "direct_link_ip_command": path_text(direct_link_ip_command)
    }))
}

// Builds the exact platform service and machine-identity provider projection.
fn setup_native(
    arguments: &InstallerArguments,
    facts: &ProbeFacts,
    path: &dyn Fn(&str) -> String,
) -> Result<Value, String> {
    let openssl = path_text(&required_dependency(facts, "openssl")?);
    if arguments.operating_system() == "linux" {
        Ok(json!({
            "platform": "linux",
            "openssl_command": openssl,
            "machine_identity_file": "/etc/machine-id",
            "watchdog_health": {
                "authority_certificate_file": path("trust/watchdog-ca.crt"),
                "controller_certificate_file": path("trust/watchdog-controller.crt"),
                "controller_private_key_file": path("trust/watchdog-controller.key")
            }
        }))
    } else {
        Ok(json!({
            "platform": "macos",
            "openssl_command": openssl,
            "machine_identity_command": path_text(&required_command_path("ioreg")?),
            "command_timeout_milliseconds": 5000,
            "command_poll_interval_milliseconds": 10
        }))
    }
}

// Builds one authority, server, and ordinary client material document.
fn mutual_tls_material(path: &dyn Fn(&str) -> String, name: &str) -> Value {
    json!({
        "authority_private_key_file": path(&format!("trust/{name}-ca.key")),
        "authority_certificate_file": path(&format!("trust/{name}-ca.crt")),
        "server_certificate_file": path(&format!("trust/{name}-server.crt")),
        "server_private_key_file": path(&format!("trust/{name}-server.key")),
        "client_certificate_file": path(&format!("trust/{name}-client.crt")),
        "client_private_key_file": path(&format!("trust/{name}-client.key"))
    })
}

// Builds the Gateway authority, server, and relay-client material document.
fn gateway_material(path: &dyn Fn(&str) -> String) -> Value {
    json!({
        "authority_private_key_file": path("trust/gateway-ca.key"),
        "authority_certificate_file": path("trust/gateway-ca.crt"),
        "server_certificate_file": path("trust/gateway-server.crt"),
        "server_private_key_file": path("trust/gateway-server.key"),
        "relay_client_certificate_file": path("trust/gateway-client.crt"),
        "relay_client_private_key_file": path("trust/gateway-client.key")
    })
}

// Builds one bounded owner-local listener configuration.
fn local_api(socket_path: &Path) -> Value {
    json!({
        "socket_path": path_text(socket_path),
        "maximum_workers": 8,
        "read_timeout_milliseconds": 1000,
        "write_timeout_milliseconds": 1000,
        "accept_poll_interval_milliseconds": 10
    })
}

// Hashes one already-verified immutable Core executable through a bounded streaming read.
fn file_sha256(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "installed Core executable is unavailable".to_string())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1024 * 1024 * 1024
    {
        return Err("installed Core executable is invalid".to_string());
    }
    let mut file =
        File::open(path).map_err(|_| "installed Core executable is unavailable".to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut observed = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "installed Core executable could not be read".to_string())?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or_else(|| "installed Core executable is oversized".to_string())?;
        if observed > metadata.len() {
            return Err("installed Core executable changed during hashing".to_string());
        }
        digest.update(&buffer[..count]);
    }
    if observed != metadata.len() {
        return Err("installed Core executable changed during hashing".to_string());
    }
    Ok(format!("{:x}", digest.finalize()))
}

// Derives one stable role-specific local peer principal from the signed Core source identity.
fn protection_principal(source_identity: &str, role: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"li_node_protection_principal_v1\0");
    digest.update(source_identity.as_bytes());
    digest.update(b"\0");
    digest.update(role.as_bytes());
    format!("{:x}", digest.finalize())[..32].to_owned()
}

// Derives one stable setup request identity from release and installation inputs.
fn setup_request_identity(
    arguments: &InstallerArguments,
    core: &CoreInstallResult,
    control_address: &str,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        "li_installer_setup_request_v1",
        arguments.selected_platform.as_str(),
        core.version.as_str(),
        core.source_identity.as_str(),
        &path_text(&arguments.letsinfer_home),
        control_address,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

// Returns one optional executable dependency as an absolute JSON path string.
fn optional_dependency(facts: &ProbeFacts, name: &str) -> Option<String> {
    facts.dependency_path(name).map(|path| path_text(&path))
}

// Resolves one required command through the current native process search path.
fn required_command_path(name: &str) -> Result<PathBuf, String> {
    command_path_if_available(name)
        .ok_or_else(|| format!("required command is unavailable: {name}"))
}

// Resolves one executable command through the inherited native search path.
fn command_path_if_available(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    command_path_in(name, &path)
}

// Returns one stable path only when every matching spelling identifies the same executable.
fn command_path_in(name: &str, path: &OsStr) -> Option<PathBuf> {
    let mut selected: Option<(PathBuf, u64, u64)> = None;
    for root in env::split_paths(path) {
        let Ok(resolved) = std::fs::canonicalize(root.join(name)) else {
            continue;
        };
        let Ok(metadata) = std::fs::metadata(&resolved) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        match selected.as_mut() {
            None => selected = Some((resolved, metadata.dev(), metadata.ino())),
            Some((path, device, inode))
                if *device == metadata.dev() && *inode == metadata.ino() =>
            {
                if resolved < *path {
                    *path = resolved;
                }
            }
            Some(_) => return None,
        }
    }
    selected.map(|(path, _, _)| path)
}

// Converts one validated absolute path into its UTF-8 setup representation.
fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

// Returns one required executable dependency from the final probe.
fn required_dependency(facts: &ProbeFacts, name: &str) -> Result<PathBuf, String> {
    facts
        .dependency_path(name)
        .ok_or_else(|| format!("required dependency is unavailable: {}", name))
}

// Returns whether one native command succeeds without inherited output.
fn command_success(command: &Path, arguments: &[&str]) -> bool {
    Command::new(command)
        .args(arguments)
        .output()
        .is_ok_and(|output| output.status.success())
}

// Returns bounded trimmed output from one successful native command.
fn command_output(command: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .map_err(|error| format!("native command could not run: {}", error))?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err(format!(
            "native command failed: {}",
            first_diagnostic(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "native command output is not UTF-8".to_string())
}

// Runs one native command and requires bounded successful completion.
fn run_checked(command: &mut Command, context: &str) -> Result<Vec<u8>, String> {
    let output = command
        .output()
        .map_err(|error| format!("{}: {}", context, error))?;
    if output.stdout.len() > 4 * 1024 * 1024 || output.stderr.len() > 4 * 1024 * 1024 {
        return Err(format!("{}: diagnostics exceeded their boundary", context));
    }
    if !output.status.success() {
        return Err(format!("{}: {}", context, first_diagnostic(&output.stderr)));
    }
    Ok(output.stdout)
}

// Returns the first nonempty bounded diagnostic line.
fn first_diagnostic(value: &[u8]) -> String {
    String::from_utf8_lossy(value)
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("command failed")
        .trim()
        .chars()
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEMPORARY_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    // Owns one unique owner-private temporary root for native setup-root tests.
    struct SetupRootFixture {
        root: PathBuf,
    }

    impl SetupRootFixture {
        // Creates one collision-rejecting private directory below the native temporary root.
        fn new() -> Self {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let root = env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root")
                .join(format!(
                    "li_installer_setup_roots_{}_{}",
                    std::process::id(),
                    sequence
                ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&root).expect("private temporary root");
            builder
                .create(root.join("core"))
                .expect("private Core root");
            Self { root }
        }

        // Returns the native owner recorded on the fixture directory.
        fn owner_user_id(&self) -> u32 {
            fs::symlink_metadata(&self.root)
                .expect("fixture metadata")
                .uid()
        }
    }

    impl Drop for SetupRootFixture {
        // Removes only this test-owned unique temporary tree after each assertion.
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    // Writes one executable fixture at an exact native path.
    fn write_executable(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("executable fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("executable fixture mode");
    }

    // Supplies one deterministic route observation and records whether it was requested.
    struct ControlAddressMock {
        result: Result<Ipv4Addr, String>,
        calls: AtomicUsize,
    }

    impl ControlAddressProvider for ControlAddressMock {
        // Returns the configured route result without reading the test host.
        fn default_route_address(&self) -> Result<Ipv4Addr, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    // Defines one deterministic child write and wait outcome below setup policy.
    struct CoreSetupChildPlan {
        completion: Result<CoreSetupProcessOutput, String>,
        write_error: Option<String>,
    }

    // Records exact input bytes while returning one injected native child observation.
    struct CoreSetupChildMock {
        input_documents: Arc<Mutex<Vec<Vec<u8>>>>,
        plan: CoreSetupChildPlan,
        wait_calls: Arc<AtomicUsize>,
    }

    impl CoreSetupChildProcess for CoreSetupChildMock {
        // Records the exact bytes before returning the injected pipe-write result.
        fn write_input(&mut self, input: &[u8]) -> Result<(), String> {
            self.input_documents
                .lock()
                .expect("input documents")
                .push(input.to_vec());
            match &self.plan.write_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        // Records mandatory child reaping and returns the injected completion observation.
        fn wait(self: Box<Self>) -> Result<CoreSetupProcessOutput, String> {
            self.wait_calls.fetch_add(1, Ordering::SeqCst);
            self.plan.completion
        }
    }

    // Supplies exact spawn and child outcomes while recording every immutable command replay.
    struct CoreSetupProcessSpawnerMock {
        commands: Mutex<Vec<CoreSetupCommand>>,
        input_documents: Arc<Mutex<Vec<Vec<u8>>>>,
        plans: Mutex<VecDeque<Result<CoreSetupChildPlan, String>>>,
        wait_calls: Arc<AtomicUsize>,
    }

    impl CoreSetupProcessSpawnerMock {
        // Creates one deterministic spawner from an exact ordered process-outcome sequence.
        fn new(plans: Vec<Result<CoreSetupChildPlan, String>>) -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                input_documents: Arc::new(Mutex::new(Vec::new())),
                plans: Mutex::new(VecDeque::from(plans)),
                wait_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        // Returns every exact command observed at the spawn boundary.
        fn commands(&self) -> Vec<CoreSetupCommand> {
            self.commands.lock().expect("commands").clone()
        }

        // Returns every exact input document observed at the child pipe boundary.
        fn input_documents(&self) -> Vec<Vec<u8>> {
            self.input_documents
                .lock()
                .expect("input documents")
                .clone()
        }

        // Returns how many successfully spawned children reached the mandatory wait boundary.
        fn wait_calls(&self) -> usize {
            self.wait_calls.load(Ordering::SeqCst)
        }
    }

    impl CoreSetupProcessSpawner for CoreSetupProcessSpawnerMock {
        // Records the command and returns the next injected spawn or child result.
        fn spawn(
            &self,
            command: &CoreSetupCommand,
        ) -> Result<Box<dyn CoreSetupChildProcess>, String> {
            self.commands
                .lock()
                .expect("commands")
                .push(command.clone());
            let plan = self
                .plans
                .lock()
                .expect("plans")
                .pop_front()
                .expect("injected process outcome")?;
            Ok(Box::new(CoreSetupChildMock {
                input_documents: self.input_documents.clone(),
                plan,
                wait_calls: self.wait_calls.clone(),
            }))
        }
    }

    // Replaces the setup home only after the authorized wrapper has admitted one native spawn.
    struct HomeReplacingCoreSetupProcessSpawner {
        delegate: CoreSetupProcessSpawnerMock,
        home: PathBuf,
        original: PathBuf,
    }

    impl CoreSetupProcessSpawner for HomeReplacingCoreSetupProcessSpawner {
        // Starts the injected child, then replaces the lexical home before child completion.
        fn spawn(
            &self,
            command: &CoreSetupCommand,
        ) -> Result<Box<dyn CoreSetupChildProcess>, String> {
            let child = self.delegate.spawn(command)?;
            fs::rename(&self.home, &self.original).expect("move admitted setup home");
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&self.home).expect("replacement setup home");
            Ok(child)
        }
    }

    // Creates one ordinary child plan from an exact completed process observation.
    fn completed_core_setup_plan(output: CoreSetupProcessOutput) -> CoreSetupChildPlan {
        CoreSetupChildPlan {
            completion: Ok(output),
            write_error: None,
        }
    }

    // Creates one exact process observation from a machine status and captured streams.
    fn core_setup_output(
        status: Option<i32>,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> CoreSetupProcessOutput {
        CoreSetupProcessOutput {
            status,
            stderr: stderr.into(),
            stdout: stdout.into(),
        }
    }

    // Creates the exact request-known result identity used by process-protocol tests.
    fn expected_core_setup_result() -> ExpectedSetupResult {
        ExpectedSetupResult {
            api_key_file: Some("/var/lib/letsinfer/material/trust/api.key".to_string()),
            control_address: "192.168.1.10".to_string(),
            display_name: "Main Node".to_string(),
            inference_endpoint: Some("http://192.168.1.10:8000".to_string()),
            role: "main".to_string(),
            services: vec!["li_node", "li_watchdog", "li_gateway"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    // Proves the advertised endpoint uses the exact submitted public-listener port.
    #[test]
    fn setup_public_binding_and_advertised_endpoint_share_one_port() {
        let binding = setup_gateway_public_address()
            .parse::<std::net::SocketAddr>()
            .expect("public listener");
        assert_eq!(
            setup_inference_endpoint("192.168.1.10"),
            format!("http://192.168.1.10:{}", binding.port())
        );
    }

    // Proves native setup submits the fixed Node, relay-Gateway, and Watchdog listener contract.
    #[test]
    fn setup_private_listener_ports_match_the_core_contract() {
        let node = setup_node_private_address()
            .parse::<std::net::SocketAddr>()
            .expect("Node private listener");
        let gateway = setup_gateway_private_address()
            .parse::<std::net::SocketAddr>()
            .expect("Gateway private listener");
        let watchdog = setup_watchdog_address()
            .parse::<std::net::SocketAddr>()
            .expect("Watchdog listener");

        assert_eq!(node.port(), 9_443);
        assert_eq!(gateway.port(), 9_444);
        assert_eq!(watchdog.port(), 9_445);
        assert!(watchdog.ip().is_loopback());
    }

    // Creates one valid closed Core setup result document for protocol tests and mutation.
    fn valid_core_setup_document() -> Value {
        let expected = expected_core_setup_result();
        json!({
            "schema": {"name": CORE_SETUP_RESULT_SCHEMA_NAME, "version": CORE_SETUP_RESULT_SCHEMA_VERSION},
            "status": "installed",
            "node_id": "0123456789abcdef0123456789abcdef",
            "machine_id": "abcdef0123456789abcdef0123456789",
            "installation_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "display_name": expected.display_name,
            "role": expected.role,
            "control_address": expected.control_address,
            "api_key_file": expected.api_key_file,
            "inference_endpoint": expected.inference_endpoint,
            "services": expected.services
        })
    }

    // Encodes one valid closed Core setup result for process-protocol tests.
    fn valid_core_setup_output() -> Vec<u8> {
        serde_json::to_vec(&valid_core_setup_document()).expect("setup result")
    }

    // Encodes the same committed identity with Core's exact replay disposition.
    fn replayed_core_setup_output() -> Vec<u8> {
        let mut document = valid_core_setup_document();
        document["status"] = json!("replayed");
        serde_json::to_vec(&document).expect("replayed setup result")
    }

    // Creates one fixed shell-free command whose identity must survive exact replay.
    fn core_setup_command() -> CoreSetupCommand {
        CoreSetupCommand::new(
            PathBuf::from("/opt/letsinfer/core/li_core_setup"),
            vec![std::ffi::OsString::from("--fixture")],
        )
    }

    // Accepts one exact committed result without an unnecessary replay.
    #[test]
    fn core_setup_protocol_accepts_one_committed_machine_result() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let input = b"exact setup input";
        let spawner = CoreSetupProcessSpawnerMock::new(vec![Ok(completed_core_setup_plan(
            core_setup_output(
                Some(CORE_SETUP_EXIT_COMMITTED),
                valid_core_setup_output(),
                Vec::new(),
            ),
        ))]);

        let result = run_core_setup_protocol(&spawner, &command, input, &expected);
        let CoreSetupProtocolResult::Committed(summary) = result else {
            panic!("committed setup result");
        };
        assert_eq!(summary.display_name, "Main Node");
        assert_eq!(summary.role, "main");
        assert_eq!(spawner.commands(), vec![command]);
        assert_eq!(spawner.input_documents(), vec![input.to_vec()]);
        assert_eq!(spawner.wait_calls(), 1);
    }

    // Rejects every structural, schema, identity, or request-binding drift in one table.
    #[test]
    fn core_setup_result_rejects_closed_contract_mutations() {
        let expected = expected_core_setup_result();
        let replace = |pointer: &str, value: Value| {
            let mut document = valid_core_setup_document();
            *document.pointer_mut(pointer).expect("fixture pointer") = value;
            document
        };
        let mut unexpected_top_level = valid_core_setup_document();
        unexpected_top_level["unexpected"] = json!(true);
        let mut missing_nullable_field = valid_core_setup_document();
        missing_nullable_field
            .as_object_mut()
            .expect("fixture object")
            .remove("api_key_file");
        let cases = vec![
            ("schema name", replace("/schema/name", json!("old_setup"))),
            ("schema version", replace("/schema/version", json!(2))),
            (
                "nested schema field",
                replace(
                    "/schema",
                    json!({"name": CORE_SETUP_RESULT_SCHEMA_NAME, "version": 1, "extra": true}),
                ),
            ),
            ("disposition", replace("/status", json!("completed"))),
            (
                "node identity",
                replace("/node_id", json!("0123456789ABCDEF0123456789ABCDEF")),
            ),
            (
                "machine identity",
                replace("/machine_id", json!("abcdef0123456789abcdef012345678")),
            ),
            (
                "installation identity",
                replace(
                    "/installation_id",
                    json!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"),
                ),
            ),
            ("display name", replace("/display_name", json!("Old Node"))),
            ("role", replace("/role", json!("child"))),
            (
                "control address",
                replace("/control_address", json!("192.168.1.11")),
            ),
            ("API key file", replace("/api_key_file", Value::Null)),
            (
                "inference endpoint",
                replace("/inference_endpoint", json!("https://192.168.1.10:8000")),
            ),
            (
                "services",
                replace("/services", json!(["li_node", "li_gateway", "li_watchdog"])),
            ),
            ("unexpected top-level field", unexpected_top_level),
            ("missing nullable field", missing_nullable_field),
        ];

        for (name, document) in cases {
            let bytes = serde_json::to_vec(&document).expect("mutated setup result");
            assert!(decode_setup_summary(&bytes, &expected).is_err(), "{name}");
        }
    }

    // Trusts the exact safe status without interpreting contradictory diagnostic text.
    #[test]
    fn core_setup_protocol_uses_only_the_safe_machine_status() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let input = b"exact setup input";
        let spawner = CoreSetupProcessSpawnerMock::new(vec![Ok(completed_core_setup_plan(
            core_setup_output(
                Some(CORE_SETUP_EXIT_SAFE_TO_ROLLBACK),
                Vec::new(),
                b"diagnostic claims recovery is required\n".to_vec(),
            ),
        ))]);

        let CoreSetupProtocolResult::SafeToRollback(reason) =
            run_core_setup_protocol(&spawner, &command, input, &expected)
        else {
            panic!("rollback-safe setup result");
        };
        assert!(reason.contains("diagnostic claims recovery"));
        assert_eq!(spawner.commands(), vec![command]);
        assert_eq!(spawner.input_documents(), vec![input.to_vec()]);
        assert_eq!(spawner.wait_calls(), 1);
    }

    // Replays every ambiguous post-spawn boundary once with byte-identical input and command.
    #[test]
    fn core_setup_protocol_reconciles_every_ambiguous_process_observation() {
        let expected = expected_core_setup_result();
        let cases = vec![
            (
                "input_write",
                CoreSetupChildPlan {
                    completion: Ok(core_setup_output(
                        Some(CORE_SETUP_EXIT_SAFE_TO_ROLLBACK),
                        Vec::new(),
                        b"rolled back\n".to_vec(),
                    )),
                    write_error: Some("injected input write failure".to_string()),
                },
            ),
            (
                "oversize",
                completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_SAFE_TO_ROLLBACK),
                    Vec::new(),
                    vec![b'x'; MAXIMUM_CORE_SETUP_ERROR_BYTES + 1],
                )),
            ),
            (
                "signal",
                completed_core_setup_plan(core_setup_output(
                    None,
                    Vec::new(),
                    b"terminated\n".to_vec(),
                )),
            ),
            (
                "unknown_status",
                completed_core_setup_plan(core_setup_output(
                    Some(47),
                    Vec::new(),
                    b"unknown\n".to_vec(),
                )),
            ),
            (
                "explicit_recovery",
                completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_RECOVERY_REQUIRED),
                    Vec::new(),
                    b"diagnostic claims rollback completed\n".to_vec(),
                )),
            ),
            (
                "malformed_success",
                completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_COMMITTED),
                    b"not json".to_vec(),
                    Vec::new(),
                )),
            ),
        ];

        for (name, first) in cases {
            let command = core_setup_command();
            let input = format!("exact setup input for {name}").into_bytes();
            let spawner = CoreSetupProcessSpawnerMock::new(vec![
                Ok(first),
                Ok(completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_COMMITTED),
                    replayed_core_setup_output(),
                    Vec::new(),
                ))),
            ]);

            assert!(matches!(
                run_core_setup_protocol(&spawner, &command, &input, &expected),
                CoreSetupProtocolResult::Committed(_)
            ));
            assert_eq!(spawner.commands(), vec![command.clone(), command], "{name}");
            assert_eq!(
                spawner.input_documents(),
                vec![input.clone(), input],
                "{name}"
            );
            assert_eq!(spawner.wait_calls(), 2, "{name}");
        }
    }

    // Refuses replay when wait failure leaves the first child termination state unproven.
    #[test]
    fn core_setup_protocol_does_not_replay_an_unreaped_child() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let input = b"exact setup input";
        for write_error in [None, Some("injected input write failure".to_string())] {
            let spawner = CoreSetupProcessSpawnerMock::new(vec![Ok(CoreSetupChildPlan {
                completion: Err("injected wait failure".to_string()),
                write_error,
            })]);

            assert!(matches!(
                run_core_setup_protocol(&spawner, &command, input, &expected),
                CoreSetupProtocolResult::RecoveryRequired(_)
            ));
            assert_eq!(spawner.commands(), vec![command.clone()]);
            assert_eq!(spawner.input_documents(), vec![input.to_vec()]);
            assert_eq!(spawner.wait_calls(), 1);
        }
    }

    // Never downgrades an observed committed status when exact replay contradicts it.
    #[test]
    fn core_setup_protocol_keeps_committed_observation_monotonic() {
        let expected = expected_core_setup_result();
        let cases = vec![
            (
                "malformed_commit",
                completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_COMMITTED),
                    b"not json".to_vec(),
                    Vec::new(),
                )),
            ),
            (
                "oversize_commit",
                completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_COMMITTED),
                    vec![b'x'; MAXIMUM_CORE_SETUP_OUTPUT_BYTES + 1],
                    Vec::new(),
                )),
            ),
            (
                "write_error_commit",
                CoreSetupChildPlan {
                    completion: Ok(core_setup_output(
                        Some(CORE_SETUP_EXIT_COMMITTED),
                        b"not json".to_vec(),
                        Vec::new(),
                    )),
                    write_error: Some("injected input write failure".to_string()),
                },
            ),
        ];

        for (name, first) in cases {
            let spawner = CoreSetupProcessSpawnerMock::new(vec![
                Ok(first),
                Ok(completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_SAFE_TO_ROLLBACK),
                    Vec::new(),
                    b"durably rolled back\n".to_vec(),
                ))),
            ]);

            let CoreSetupProtocolResult::RecoveryRequired(reason) = run_core_setup_protocol(
                &spawner,
                &core_setup_command(),
                b"exact setup input",
                &expected,
            ) else {
                panic!("monotonic committed observation for {name}");
            };
            assert!(
                reason.contains("committed result contradicted exact reconciliation"),
                "{name}"
            );
            assert_eq!(spawner.commands().len(), 2, "{name}");
            assert_eq!(spawner.wait_calls(), 2, "{name}");
        }
    }

    // Allows rollback after an ambiguous attempt only when exact replay returns the safe class.
    #[test]
    fn core_setup_protocol_accepts_exact_reconciliation_rollback() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let input = b"exact setup input";
        let spawner = CoreSetupProcessSpawnerMock::new(vec![
            Ok(completed_core_setup_plan(core_setup_output(
                Some(CORE_SETUP_EXIT_RECOVERY_REQUIRED),
                Vec::new(),
                b"ambiguous\n".to_vec(),
            ))),
            Ok(completed_core_setup_plan(core_setup_output(
                Some(CORE_SETUP_EXIT_SAFE_TO_ROLLBACK),
                Vec::new(),
                b"durably rolled back\n".to_vec(),
            ))),
        ]);

        let CoreSetupProtocolResult::SafeToRollback(reason) =
            run_core_setup_protocol(&spawner, &command, input, &expected)
        else {
            panic!("reconciled rollback-safe result");
        };
        assert!(reason.contains("exact reconciliation proved rollback-safe"));
        assert_eq!(spawner.wait_calls(), 2);
    }

    // Preserves activation when the one exact reconciliation attempt remains ambiguous.
    #[test]
    fn core_setup_protocol_stops_after_one_ambiguous_reconciliation() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let input = b"exact setup input";
        for second in [
            Err("injected replay spawn failure".to_string()),
            Ok(completed_core_setup_plan(core_setup_output(
                Some(CORE_SETUP_EXIT_RECOVERY_REQUIRED),
                Vec::new(),
                b"still ambiguous\n".to_vec(),
            ))),
        ] {
            let spawner = CoreSetupProcessSpawnerMock::new(vec![
                Ok(completed_core_setup_plan(core_setup_output(
                    Some(CORE_SETUP_EXIT_RECOVERY_REQUIRED),
                    Vec::new(),
                    b"first ambiguity\n".to_vec(),
                ))),
                second,
            ]);

            let CoreSetupProtocolResult::RecoveryRequired(reason) =
                run_core_setup_protocol(&spawner, &command, input, &expected)
            else {
                panic!("recovery-required setup result");
            };
            assert!(reason.contains("requires recovery after exact reconciliation"));
            assert_eq!(spawner.commands().len(), 2);
        }
    }

    // Leaves a first spawn failure rollback-safe because no Core setup process began.
    #[test]
    fn core_setup_protocol_distinguishes_a_process_that_never_started() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let spawner =
            CoreSetupProcessSpawnerMock::new(vec![Err("injected first spawn failure".to_string())]);

        assert!(matches!(
            run_core_setup_protocol(&spawner, &command, b"exact setup input", &expected),
            CoreSetupProtocolResult::NotStarted(reason)
                if reason == "injected first spawn failure"
        ));
        assert_eq!(spawner.commands(), vec![command]);
        assert!(spawner.input_documents().is_empty());
        assert_eq!(spawner.wait_calls(), 0);
    }

    // Refuses drift before spawn and converts drift across child completion into recovery-required.
    #[test]
    fn core_setup_process_authority_is_validated_before_and_after_spawn() {
        let command = core_setup_command();
        let expected = expected_core_setup_result();
        let input = b"exact setup input";

        let before = SetupRootFixture::new();
        let before_home = before.root.join("before-home");
        let before_original = before.root.join("before-original");
        let before_preparation = SetupRootPreparation::claim(&before_home, before.owner_user_id())
            .expect("before-spawn receipt");
        fs::rename(&before_home, &before_original).expect("move before-spawn home");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&before_home)
            .expect("before-spawn replacement");
        let before_spawner = CoreSetupProcessSpawnerMock::new(Vec::new());
        let before_error = match run_core_setup_protocol_with_authority(
            &before_spawner,
            &before_preparation,
            &before_home,
            &command,
            input,
            &expected,
        ) {
            Err(error) => error,
            Ok(_) => panic!("drift before spawn must fail"),
        };
        assert!(before_error.contains("changed across process completion"));
        assert!(before_spawner.commands().is_empty());

        let after = SetupRootFixture::new();
        let after_home = after.root.join("after-home");
        let after_preparation = SetupRootPreparation::claim(&after_home, after.owner_user_id())
            .expect("after-spawn receipt");
        let after_spawner = HomeReplacingCoreSetupProcessSpawner {
            delegate: CoreSetupProcessSpawnerMock::new(vec![Ok(completed_core_setup_plan(
                core_setup_output(
                    Some(CORE_SETUP_EXIT_COMMITTED),
                    valid_core_setup_output(),
                    Vec::new(),
                ),
            ))]),
            home: after_home.clone(),
            original: after.root.join("after-original"),
        };
        let after_error = match run_core_setup_protocol_with_authority(
            &after_spawner,
            &after_preparation,
            &after_home,
            &command,
            input,
            &expected,
        ) {
            Err(error) => error,
            Ok(_) => panic!("drift after spawn must fail"),
        };
        assert!(after_error.contains("changed across process completion"));
        assert_eq!(after_spawner.delegate.commands(), vec![command]);
        assert_eq!(after_spawner.delegate.wait_calls(), 1);
    }

    // Proves automatic setup consumes exactly one injected default-route observation.
    #[test]
    fn automatic_control_address_uses_the_injected_route() {
        let provider = ControlAddressMock {
            result: Ok(Ipv4Addr::new(192, 168, 1, 66)),
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            resolve_control_address(&ControlAddressSelection::Automatic, &provider)
                .expect("automatic address"),
            "192.168.1.66"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    // Proves the installer handoff names the closed root accepted by Node and Watchdog.
    #[test]
    fn watchdog_protection_root_matches_the_native_provider_contract() {
        assert_eq!(
            watchdog_protection_root(Path::new("/var/lib/letsinfer/material")),
            PathBuf::from("/var/lib/letsinfer/material/watchdog/protected-placements")
        );
    }

    // Proves the installer handoff names the closed staging root accepted by pairing.
    #[test]
    fn pairing_trust_workspace_matches_the_native_provider_contract() {
        assert_eq!(
            pairing_trust_workspace(Path::new("/var/lib/letsinfer/trust-workspace")),
            PathBuf::from("/var/lib/letsinfer/trust-workspace/pairing_trust_staging")
        );
    }

    // Proves the default source names the signed catalog document consumed by RuntimeManager.
    #[test]
    fn runtime_catalog_source_matches_the_signed_provider_contract() {
        assert_eq!(
            RUNTIME_CATALOG_SOURCE,
            "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json"
        );
    }

    // Preserves the service-mode Avahi entry from probe facts into generated Node input.
    #[test]
    fn linux_pairing_setup_preserves_avahi_service_symlink_entry() {
        let fixture = SetupRootFixture::new();
        let executable = fixture.root.join("avahi-publish");
        let service_entry = fixture.root.join("avahi-publish-service");
        write_executable(&executable, b"service publisher\n");
        symlink(&executable, &service_entry).expect("service-mode command entry");
        let facts = ProbeFacts::from_test_document(json!({
            "dependencies": {
                "avahi_publish_service": {
                    "path": path_text(&service_entry)
                }
            }
        }));

        let pairing =
            setup_linux_pairing(&facts, Path::new("/usr/bin/ip")).expect("Linux pairing input");

        assert_eq!(pairing["discovery_command"], path_text(&service_entry));
        assert_ne!(
            pairing["discovery_command"],
            path_text(&fs::canonicalize(&service_entry).expect("publisher target"))
        );
    }

    // Produces identical setup bytes for equivalent usr/bin and usr/sbin executable spellings.
    #[test]
    fn setup_command_resolution_normalizes_equivalent_usr_bin_and_usr_sbin_inodes() {
        let fixture = SetupRootFixture::new();
        let binary_root = fixture.root.join("usr/bin");
        let system_binary_root = fixture.root.join("usr/sbin");
        fs::create_dir_all(&binary_root).expect("usr bin");
        fs::create_dir_all(&system_binary_root).expect("usr sbin");
        let binary_command = binary_root.join("ip");
        let system_binary_command = system_binary_root.join("ip");
        write_executable(&system_binary_command, b"equivalent executable\n");
        fs::hard_link(&system_binary_command, &binary_command).expect("equivalent command link");
        let binary_first = env::join_paths([&binary_root, &system_binary_root]).expect("PATH");
        let system_binary_first =
            env::join_paths([&system_binary_root, &binary_root]).expect("reordered PATH");

        let first = json!({
            "direct_link_ip_command": path_text(
                &command_path_in("ip", &binary_first).expect("binary-first resolution")
            )
        });
        let replay = json!({
            "direct_link_ip_command": path_text(
                &command_path_in("ip", &system_binary_first).expect("system-binary-first resolution")
            )
        });

        assert_eq!(
            serde_json::to_vec(&first).expect("first setup bytes"),
            serde_json::to_vec(&replay).expect("replayed setup bytes")
        );
        assert_eq!(
            first["direct_link_ip_command"],
            path_text(&std::fs::canonicalize(binary_command).expect("canonical command"))
        );
    }

    // Rejects a PATH containing two genuine command identities instead of choosing by order.
    #[test]
    fn setup_command_resolution_rejects_divergent_usr_bin_and_usr_sbin_executables() {
        let fixture = SetupRootFixture::new();
        let binary_root = fixture.root.join("usr/bin");
        let system_binary_root = fixture.root.join("usr/sbin");
        fs::create_dir_all(&binary_root).expect("usr bin");
        fs::create_dir_all(&system_binary_root).expect("usr sbin");
        write_executable(&binary_root.join("ip"), b"binary executable\n");
        write_executable(
            &system_binary_root.join("ip"),
            b"system binary executable\n",
        );
        let binary_first = env::join_paths([&binary_root, &system_binary_root]).expect("PATH");
        let system_binary_first =
            env::join_paths([&system_binary_root, &binary_root]).expect("reordered PATH");

        assert_eq!(command_path_in("ip", &binary_first), None);
        assert_eq!(command_path_in("ip", &system_binary_first), None);
    }

    // Proves an explicit validated address bypasses native route observation.
    #[test]
    fn explicit_control_address_bypasses_the_native_route() {
        let provider = ControlAddressMock {
            result: Err("must not be called".to_string()),
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            resolve_control_address(
                &ControlAddressSelection::Explicit("homeai.local".to_string()),
                &provider,
            )
            .expect("explicit address"),
            "homeai.local"
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    // Proves a provider cannot turn a loopback or failed observation into node identity.
    #[test]
    fn automatic_control_address_fails_closed() {
        for result in [
            Ok(Ipv4Addr::LOCALHOST),
            Ok(Ipv4Addr::UNSPECIFIED),
            Ok(Ipv4Addr::new(224, 0, 0, 1)),
            Err("route unavailable".to_string()),
        ] {
            let provider = ControlAddressMock {
                result,
                calls: AtomicUsize::new(0),
            };
            assert!(
                resolve_control_address(&ControlAddressSelection::Automatic, &provider).is_err()
            );
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        }
    }

    // Proves fresh setup creates the complete installer-owned private root closure.
    #[test]
    fn setup_root_preparation_creates_every_required_private_directory() {
        let fixture = SetupRootFixture::new();
        let owner_user_id = fixture.owner_user_id();
        let preparation =
            SetupRootPreparation::prepare(&fixture.root, owner_user_id).expect("prepared roots");
        for name in ["setup", "material", "configuration"] {
            open_private_directory(&fixture.root.join(name), owner_user_id)
                .expect("private setup root");
        }
        open_private_directory(&fixture.root.join("core/.uninstall"), owner_user_id)
            .expect("private uninstall root");
        assert!(!fixture.root.join("trust-workspace").exists());
        preparation.rollback().expect("root rollback");
        for name in ["setup", "material", "configuration"] {
            assert!(!fixture.root.join(name).exists());
        }
        assert!(!fixture.root.join("core/.uninstall").exists());
        assert!(fixture.root.join("core").is_dir());
    }

    // Proves an exact existing root closure replays without claiming prior directories.
    #[test]
    fn setup_root_preparation_replays_without_removing_existing_roots() {
        let fixture = SetupRootFixture::new();
        let owner_user_id = fixture.owner_user_id();
        let original =
            SetupRootPreparation::prepare(&fixture.root, owner_user_id).expect("original roots");
        fs::write(fixture.root.join("material/sentinel"), b"existing state")
            .expect("existing sentinel");
        let replay =
            SetupRootPreparation::prepare(&fixture.root, owner_user_id).expect("replayed roots");
        replay.rollback().expect("replay rollback");
        for name in ["setup", "material", "configuration"] {
            assert!(fixture.root.join(name).is_dir());
        }
        assert!(fixture.root.join("core/.uninstall").is_dir());
        assert_eq!(
            fs::read(fixture.root.join("material/sentinel")).expect("existing sentinel"),
            b"existing state"
        );
        original.rollback().expect("original rollback");
    }

    // Proves unsafe existing types, modes, and owners are rejected without replacement.
    #[test]
    fn setup_root_preparation_rejects_unsafe_existing_metadata() {
        let regular = SetupRootFixture::new();
        fs::write(regular.root.join("setup"), b"not a directory").expect("regular setup path");
        assert!(SetupRootPreparation::prepare(&regular.root, regular.owner_user_id()).is_err());
        assert!(regular.root.join("setup").is_file());

        let linked = SetupRootFixture::new();
        let target = linked.root.join("target");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&target).expect("link target");
        symlink(&target, linked.root.join("setup")).expect("setup link");
        assert!(SetupRootPreparation::prepare(&linked.root, linked.owner_user_id()).is_err());
        assert!(fs::symlink_metadata(linked.root.join("setup"))
            .expect("link metadata")
            .file_type()
            .is_symlink());

        for mode in [0o755, 0o1700] {
            let unsafe_mode = SetupRootFixture::new();
            builder
                .create(unsafe_mode.root.join("setup"))
                .expect("unsafe-mode setup root");
            fs::set_permissions(
                unsafe_mode.root.join("setup"),
                fs::Permissions::from_mode(mode),
            )
            .expect("unsafe mode");
            assert!(
                SetupRootPreparation::prepare(&unsafe_mode.root, unsafe_mode.owner_user_id())
                    .is_err()
            );
            assert_eq!(
                fs::symlink_metadata(unsafe_mode.root.join("setup"))
                    .expect("unsafe-mode metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                mode
            );
        }

        let foreign = SetupRootFixture::new();
        assert!(SetupRootPreparation::prepare(
            &foreign.root,
            foreign.owner_user_id().wrapping_add(1)
        )
        .is_err());
        assert!(foreign.root.is_dir());

        for nested in ["regular", "symbolic", "unsafe-mode"] {
            let fixture = SetupRootFixture::new();
            let uninstall = fixture.root.join("core/.uninstall");
            match nested {
                "regular" => fs::write(&uninstall, b"not a directory").expect("regular root"),
                "symbolic" => {
                    let target = fixture.root.join("target-uninstall");
                    builder.create(&target).expect("nested target");
                    symlink(&target, &uninstall).expect("nested link");
                }
                "unsafe-mode" => {
                    builder.create(&uninstall).expect("nested root");
                    fs::set_permissions(&uninstall, fs::Permissions::from_mode(0o755))
                        .expect("nested mode");
                }
                _ => unreachable!(),
            }
            assert!(
                SetupRootPreparation::prepare(&fixture.root, fixture.owner_user_id()).is_err(),
                "nested={nested}"
            );
            assert!(fs::symlink_metadata(&uninstall).is_ok(), "nested={nested}");
        }
    }

    // Proves a later invalid root compensates only an earlier directory created in this attempt.
    #[test]
    fn setup_root_preparation_rolls_back_partial_creation() {
        let fixture = SetupRootFixture::new();
        fs::write(fixture.root.join("material"), b"foreign material")
            .expect("invalid material path");
        assert!(SetupRootPreparation::prepare(&fixture.root, fixture.owner_user_id()).is_err());
        assert!(!fixture.root.join("setup").exists());
        assert!(fixture.root.join("material").is_file());
        assert!(!fixture.root.join("configuration").exists());
    }

    // Proves each post-mkdir failure removes only its exact attempt-owned directory identity.
    #[test]
    fn private_directory_creation_failures_leave_no_orphan() {
        let parent_fixture = SetupRootFixture::new();
        let parent = parent_fixture.root.join("created-parent");
        inject_private_directory_failure(
            "installation home parent",
            PrivateDirectoryFailurePoint::BeforeSync,
        );
        assert!(
            SetupRootPreparation::claim(&parent.join("home"), parent_fixture.owner_user_id(),)
                .is_err()
        );
        assert!(!parent.exists());

        for (name, point) in [
            ("before-open", PrivateDirectoryFailurePoint::BeforeOpen),
            (
                "before-metadata",
                PrivateDirectoryFailurePoint::BeforeMetadata,
            ),
            ("after-create", PrivateDirectoryFailurePoint::AfterCreate),
        ] {
            let home_fixture = SetupRootFixture::new();
            let home = home_fixture.root.join(name);
            inject_private_directory_failure("installation home", point);
            assert!(SetupRootPreparation::claim(&home, home_fixture.owner_user_id()).is_err());
            assert!(!home.exists(), "scenario={name}");
        }

        let child_fixture = SetupRootFixture::new();
        let mut child_preparation =
            SetupRootPreparation::claim(&child_fixture.root, child_fixture.owner_user_id())
                .expect("existing home receipt");
        inject_private_directory_failure("root", PrivateDirectoryFailurePoint::AfterOpen);
        assert!(child_preparation.complete().is_err());
        assert!(!child_fixture.root.join("setup").exists());

        let quarantine_fixture = SetupRootFixture::new();
        let quarantine_home = quarantine_fixture.root.join("created-home");
        let mut quarantine_preparation =
            SetupRootPreparation::claim(&quarantine_home, quarantine_fixture.owner_user_id())
                .expect("fresh home receipt");
        inject_private_directory_failure(
            "home quarantine",
            PrivateDirectoryFailurePoint::BeforeSync,
        );
        assert!(quarantine_preparation.cleanup_created_home().is_err());
        assert!(quarantine_home.is_dir());
        assert!(fs::read_dir(&quarantine_fixture.root)
            .expect("quarantine fixture entries")
            .all(|entry| !entry
                .expect("quarantine fixture entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".li_installer_home_rollback_")));
        quarantine_preparation
            .cleanup_created_home()
            .expect("retry exact home cleanup");

        let ancestor_fixture = SetupRootFixture::new();
        let ancestor = ancestor_fixture.root.join("attempt-parent");
        let mut ancestor_preparation =
            SetupRootPreparation::claim(&ancestor.join("home"), ancestor_fixture.owner_user_id())
                .expect("fresh ancestor receipt");
        ancestor_preparation
            .cleanup_created_home()
            .expect("fresh ancestor cleanup");
        assert!(!ancestor.exists());
    }

    // Proves serialized creation restores the caller's umask while producing exact 0700 roots.
    #[test]
    fn setup_root_preparation_overrides_a_restrictive_umask() {
        const CHILD_ENVIRONMENT: &str = "LI_INSTALLER_RESTRICTIVE_UMASK_CHILD";
        if env::var_os(CHILD_ENVIRONMENT).is_some() {
            let fixture = SetupRootFixture::new();
            let previous_umask = unsafe { libc::umask(0o777) };
            let preparation = SetupRootPreparation::prepare(&fixture.root, fixture.owner_user_id())
                .expect("prepared roots under restrictive umask");
            let restored_umask = unsafe { libc::umask(previous_umask) };
            assert_eq!(restored_umask, 0o777);
            for name in ["setup", "material", "configuration"] {
                open_private_directory(&fixture.root.join(name), fixture.owner_user_id())
                    .expect("private root under restrictive umask");
            }
            open_private_directory(
                &fixture.root.join("core/.uninstall"),
                fixture.owner_user_id(),
            )
            .expect("private uninstall root under restrictive umask");
            preparation.rollback().expect("restrictive-umask rollback");
            return;
        }
        let output = Command::new(env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "li_installer_service_manager::tests::setup_root_preparation_overrides_a_restrictive_umask",
                "--nocapture",
            ])
            .env(CHILD_ENVIRONMENT, "1")
            .output()
            .expect("restrictive-umask child");
        assert!(
            output.status.success(),
            "restrictive-umask child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Proves rollback preserves nonempty Core state while removing other empty created roots.
    #[test]
    fn setup_root_rollback_preserves_nonempty_state() {
        let fixture = SetupRootFixture::new();
        let preparation = SetupRootPreparation::prepare(&fixture.root, fixture.owner_user_id())
            .expect("prepared roots");
        fs::write(fixture.root.join("material/retained"), b"Core state").expect("retained state");
        fs::write(
            fixture
                .root
                .join("core/.uninstall/li_core_uninstall_session_v1.json"),
            b"recovery journal",
        )
        .expect("recovery journal");
        preparation.rollback().expect("conservative rollback");
        assert!(fixture.root.join("material/retained").is_file());
        assert!(fixture
            .root
            .join("core/.uninstall/li_core_uninstall_session_v1.json")
            .is_file());
        assert!(!fixture.root.join("setup").exists());
        assert!(!fixture.root.join("configuration").exists());
    }

    // Proves rollback refuses a same-name replacement instead of deleting foreign state.
    #[test]
    fn setup_root_rollback_rejects_replaced_directory_identity() {
        let fixture = SetupRootFixture::new();
        let preparation = SetupRootPreparation::prepare(&fixture.root, fixture.owner_user_id())
            .expect("prepared roots");
        fs::rename(
            fixture.root.join("material"),
            fixture.root.join("original-material"),
        )
        .expect("move original material");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(fixture.root.join("material"))
            .expect("replacement material");
        assert!(preparation.rollback().is_err());
        assert!(fixture.root.join("material").is_dir());
        assert!(fixture.root.join("original-material").is_dir());
    }

    // Removes one nonempty fresh home through its exact quarantine after confirmed rollback.
    #[test]
    fn fresh_setup_home_cleanup_removes_only_the_attempt_owned_nonempty_tree() {
        let fixture = SetupRootFixture::new();
        let home = fixture.root.join("fresh-home");
        let external = fixture.root.join("external");
        let mut preparation =
            SetupRootPreparation::claim(&home, fixture.owner_user_id()).expect("fresh home claim");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&external).expect("external root");
        fs::write(external.join("sentinel"), b"outside fresh home").expect("external sentinel");
        builder.create(home.join("core")).expect("Core root");
        preparation.complete().expect("complete setup roots");
        builder
            .create(home.join("material/state"))
            .expect("state root");
        fs::write(
            home.join("material/state/li_core.sqlite3"),
            b"private state",
        )
        .expect("private state");
        builder
            .create(home.join("core/versions"))
            .expect("immutable version root");
        fs::write(home.join("core/versions/li_node"), b"immutable Core").expect("immutable Core");
        fs::set_permissions(
            home.join("core/versions"),
            fs::Permissions::from_mode(0o555),
        )
        .expect("immutable version mode");
        symlink(&external, home.join("material/external-link")).expect("internal symlink");

        preparation
            .cleanup_created_home()
            .expect("fresh-home cleanup");

        assert!(!home.exists());
        assert_eq!(
            fs::read(external.join("sentinel")).expect("external sentinel retained"),
            b"outside fresh home"
        );
        assert!(fs::read_dir(&fixture.root)
            .expect("fixture entries")
            .all(|entry| !entry
                .expect("fixture entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".li_installer_home_rollback_")));
    }

    // Resumes each published cleanup phase without revisiting a vanished or replaced home path.
    #[test]
    fn fresh_setup_home_cleanup_replays_every_partial_phase() {
        for (name, point, replace_home) in [
            (
                "after-rename",
                FreshHomeCleanupFailurePoint::AfterRename,
                true,
            ),
            (
                "during-traversal",
                FreshHomeCleanupFailurePoint::DuringTraversal,
                false,
            ),
            (
                "after-home-unlink",
                FreshHomeCleanupFailurePoint::AfterHomeUnlink,
                false,
            ),
            (
                "before-parent-cleanup",
                FreshHomeCleanupFailurePoint::BeforeParentCleanup,
                false,
            ),
        ] {
            let fixture = SetupRootFixture::new();
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            let external = fixture.root.join("external");
            builder.create(&external).expect("external directory");
            fs::write(external.join("sentinel"), b"foreign").expect("external sentinel");
            let ancestor = fixture.root.join(format!("attempt-{name}"));
            let home = if replace_home {
                fixture.root.join(format!("home-{name}"))
            } else {
                ancestor.join("home")
            };
            let mut preparation = SetupRootPreparation::claim(&home, fixture.owner_user_id())
                .expect("fresh replay receipt");
            fs::write(home.join("private-state"), b"attempt-owned").expect("private state");
            symlink(&external, home.join("external-link")).expect("foreign link");
            inject_fresh_home_cleanup_failure(point);

            assert!(
                preparation.cleanup_created_home().is_err(),
                "scenario={name}"
            );
            if replace_home {
                builder.create(&home).expect("replacement home");
                fs::write(home.join("replacement-sentinel"), b"replacement")
                    .expect("replacement sentinel");
            }
            preparation
                .cleanup_created_home()
                .expect("replayed fresh-home cleanup");

            assert_eq!(
                fs::read(external.join("sentinel")).expect("foreign sentinel retained"),
                b"foreign",
                "scenario={name}"
            );
            if replace_home {
                assert_eq!(
                    fs::read(home.join("replacement-sentinel")).expect("replacement retained"),
                    b"replacement"
                );
            } else {
                assert!(!ancestor.exists(), "scenario={name}");
            }
            assert!(fs::read_dir(&fixture.root)
                .expect("fixture entries")
                .all(|entry| !entry
                    .expect("fixture entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".li_installer_home_rollback_")));
        }
    }

    // Rejects lexical aliases and parent or final symlinks before claiming cleanup authority.
    #[test]
    fn setup_home_claim_rejects_alias_and_symlink_containment() {
        let fixture = SetupRootFixture::new();
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        let linked_parent_target = fixture.root.join("linked-parent-target");
        builder
            .create(&linked_parent_target)
            .expect("linked parent target");
        let linked_parent = fixture.root.join("linked-parent");
        symlink(&linked_parent_target, &linked_parent).expect("linked parent");
        let final_target = fixture.root.join("final-target");
        builder.create(&final_target).expect("final target");
        let final_link = fixture.root.join("final-link");
        symlink(&final_target, &final_link).expect("final link");

        for (name, path) in [
            ("current", fixture.root.join("./alias-home")),
            ("parent", fixture.root.join("child/../alias-home")),
            ("parent-symlink", linked_parent.join("home")),
            ("final-symlink", final_link),
        ] {
            assert!(
                SetupRootPreparation::claim(&path, fixture.owner_user_id()).is_err(),
                "scenario={name}"
            );
        }
    }

    // Preserves every byte of a pre-existing home because it carries no cleanup authority.
    #[test]
    fn preexisting_setup_home_cleanup_preserves_private_state() {
        let fixture = SetupRootFixture::new();
        let mut preparation = SetupRootPreparation::claim(&fixture.root, fixture.owner_user_id())
            .expect("existing home claim");
        preparation.complete().expect("complete existing roots");
        fs::write(
            fixture.root.join("material/sentinel"),
            b"pre-existing state",
        )
        .expect("existing sentinel");

        preparation
            .cleanup_created_home()
            .expect("no-op existing-home cleanup");

        assert_eq!(
            fs::read(fixture.root.join("material/sentinel")).expect("retained sentinel"),
            b"pre-existing state"
        );
        assert!(fixture.root.join("core").is_dir());
    }

    // Refuses a replaced home while retaining descriptor authority across an ancestor rename.
    #[test]
    fn fresh_setup_home_cleanup_fails_closed_on_root_replacement() {
        let fixture = SetupRootFixture::new();
        let home = fixture.root.join("fresh-home");
        let original = fixture.root.join("original-home");
        let mut preparation =
            SetupRootPreparation::claim(&home, fixture.owner_user_id()).expect("fresh home claim");
        fs::rename(&home, &original).expect("move claimed home");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&home).expect("replacement home");
        fs::write(home.join("sentinel"), b"replacement").expect("replacement sentinel");

        let error = preparation
            .cleanup_created_home()
            .expect_err("replacement must fail closed");

        assert!(error.contains("changed before rollback"));
        assert_eq!(
            fs::read(home.join("sentinel")).expect("replacement retained"),
            b"replacement"
        );
        assert!(original.is_dir());

        let parent = fixture.root.join("claimed-parent");
        builder.create(&parent).expect("claimed parent");
        let parent_home = parent.join("fresh-home");
        let original_parent = fixture.root.join("original-parent");
        let mut parent_preparation =
            SetupRootPreparation::claim(&parent_home, fixture.owner_user_id())
                .expect("parent receipt");
        fs::rename(&parent, &original_parent).expect("move claimed parent");
        symlink(&original_parent, &parent).expect("replacement parent symlink");
        parent_preparation
            .cleanup_created_home()
            .expect("descriptor-owned home cleanup after parent rename");
        assert!(parent.is_symlink());
        assert!(!original_parent.join("fresh-home").exists());
    }
}
