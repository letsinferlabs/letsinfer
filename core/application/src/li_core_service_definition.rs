// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::{CoreProcessPlatform, CoreResidentProcess, CoreResidentProcessCommand};

const SERVICE_DEFINITION_MODE: u32 = 0o600;
const MAXIMUM_SERVICE_DEFINITION_BYTES: usize = 64 * 1024;

// Defines the provisional legacy resource envelope for one independently supervised resident.
struct SystemdProcessProfile {
    memory_high_bytes: u64,
    memory_max_bytes: u64,
    restart_seconds: u8,
    stop_timeout_seconds: u8,
    additional_directives: &'static str,
}

// Carries one complete deterministic native supervisor document and its content identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceDefinition {
    process: CoreResidentProcess,
    service_identity: &'static str,
    filename: String,
    mode: u32,
    bytes: Vec<u8>,
    sha256: Sha256Digest,
    memory_max_bytes: Option<u64>,
    executable: PathBuf,
    arguments: Vec<OsString>,
}

impl CoreServiceDefinition {
    // Creates one bounded content-addressed definition after validating its external identity.
    fn new(
        process: CoreResidentProcess,
        service_identity: &'static str,
        filename: String,
        bytes: Vec<u8>,
        memory_max_bytes: Option<u64>,
        executable: PathBuf,
        arguments: Vec<OsString>,
    ) -> Result<Self, CoreServiceDefinitionError> {
        if filename.is_empty()
            || filename.contains('/')
            || filename.contains('\\')
            || bytes.is_empty()
            || bytes.len() > MAXIMUM_SERVICE_DEFINITION_BYTES
            || bytes.contains(&0)
        {
            return Err(CoreServiceDefinitionError::InvalidDefinition);
        }
        let sha256 = Sha256Digest::parse(&format!("{:x}", Sha256::digest(&bytes)))
            .map_err(|_| CoreServiceDefinitionError::InvalidDefinition)?;
        Ok(Self {
            process,
            service_identity,
            filename,
            mode: SERVICE_DEFINITION_MODE,
            bytes,
            sha256,
            memory_max_bytes,
            executable,
            arguments,
        })
    }

    // Returns the resident process owned by this definition.
    pub const fn process(&self) -> CoreResidentProcess {
        self.process
    }

    // Returns the exact native service identity.
    pub const fn service_identity(&self) -> &'static str {
        self.service_identity
    }

    // Returns the contained filename installed under the platform service root.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    // Returns the private service-definition mode required at installation.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    // Returns the exact deterministic supervisor bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Returns the content identity used by CoreUpdate snapshot and readiness checks.
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    // Returns the exact native hard memory ceiling emitted into this definition when available.
    pub const fn memory_max_bytes(&self) -> Option<u64> {
        self.memory_max_bytes
    }

    // Returns the immutable executable expected in the loaded native process identity.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns the exact shell-free arguments expected in the loaded native process identity.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

// Generates platform definitions only from the stable resident-process command contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreServiceDefinitionProvider;

impl CoreServiceDefinitionProvider {
    // Generates one deterministic systemd unit or launchd agent without inspecting the host.
    pub fn definition(
        &self,
        platform: CoreProcessPlatform,
        command: &CoreResidentProcessCommand,
    ) -> Result<CoreServiceDefinition, CoreServiceDefinitionError> {
        match platform {
            CoreProcessPlatform::Linux => systemd_definition(command),
            CoreProcessPlatform::Macos => launchd_definition(command),
        }
    }
}

// Describes one unsupported or unsafe service-definition request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreServiceDefinitionError {
    PlatformIdentityMismatch,
    InvalidDefinition,
    UnsafeArgument,
}

impl fmt::Display for CoreServiceDefinitionError {
    // Presents stable service-generation language without machine paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlatformIdentityMismatch => {
                formatter.write_str("the Core service identity does not match its platform")
            }
            Self::InvalidDefinition => {
                formatter.write_str("the Core service definition is invalid")
            }
            Self::UnsafeArgument => formatter.write_str("a Core service argument is unsafe"),
        }
    }
}

impl Error for CoreServiceDefinitionError {}

// Generates one user-scoped systemd unit with fixed restart and privilege boundaries.
fn systemd_definition(
    command: &CoreResidentProcessCommand,
) -> Result<CoreServiceDefinition, CoreServiceDefinitionError> {
    if command.service_identity() != command.process().linux_service_identity() {
        return Err(CoreServiceDefinitionError::PlatformIdentityMismatch);
    }
    let executable = systemd_argument(command.executable().as_os_str())?;
    let arguments = command
        .arguments()
        .iter()
        .map(|argument| systemd_argument(argument.as_os_str()))
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let description = process_description(command.process());
    let unit_dependencies = systemd_unit_dependencies(command.process());
    let address_families = process_address_families(command.process());
    let profile = systemd_process_profile(command.process());
    let bytes = format!(
        "[Unit]\nDescription={description}\n{unit_dependencies}StartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart={executable} {arguments}\nRestart=always\nRestartSec={}s\nTimeoutStopSec={}s\nKillMode=mixed\nMemoryAccounting=true\nMemoryHigh={}\nMemoryMax={}\nMemorySwapMax=0\n{}NoNewPrivileges=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nRestrictRealtime=true\nRestrictAddressFamilies={address_families}\nSystemCallArchitectures=native\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",
        profile.restart_seconds,
        profile.stop_timeout_seconds,
        profile.memory_high_bytes,
        profile.memory_max_bytes,
        profile.additional_directives,
    )
    .into_bytes();
    CoreServiceDefinition::new(
        command.process(),
        command.service_identity(),
        command.service_identity().to_string(),
        bytes,
        Some(profile.memory_max_bytes),
        command.executable().to_path_buf(),
        command.arguments().to_vec(),
    )
}

// Orders Linux startup by safety responsibility without coupling independent restarts.
const fn systemd_unit_dependencies(process: CoreResidentProcess) -> &'static str {
    match process {
        CoreResidentProcess::Node => {
            "After=network-online.target\nWants=network-online.target\n"
        }
        CoreResidentProcess::Watchdog => {
            "After=network-online.target li_node.service\nWants=network-online.target li_node.service\n"
        }
        CoreResidentProcess::Gateway => {
            "After=network-online.target li_node.service li_watchdog.service\nWants=network-online.target li_node.service li_watchdog.service\n"
        }
    }
}

// Generates one user launch agent with a closed executable and argument array.
fn launchd_definition(
    command: &CoreResidentProcessCommand,
) -> Result<CoreServiceDefinition, CoreServiceDefinitionError> {
    if command.process().macos_service_identity() != Some(command.service_identity()) {
        return Err(CoreServiceDefinitionError::PlatformIdentityMismatch);
    }
    let mut arguments = Vec::with_capacity(command.arguments().len() + 1);
    arguments.push(xml_argument(command.executable().as_os_str())?);
    for argument in command.arguments() {
        arguments.push(xml_argument(argument)?);
    }
    let argument_elements = arguments
        .into_iter()
        .map(|argument| format!("    <string>{argument}</string>\n"))
        .collect::<String>();
    let label = xml_text(command.service_identity())?;
    let standard_output = xml_argument(
        command
            .standard_output()
            .ok_or(CoreServiceDefinitionError::PlatformIdentityMismatch)?
            .as_os_str(),
    )?;
    let standard_error = xml_argument(
        command
            .standard_error()
            .ok_or(CoreServiceDefinitionError::PlatformIdentityMismatch)?
            .as_os_str(),
    )?;
    let bytes = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{label}</string>\n  <key>ProgramArguments</key>\n  <array>\n{argument_elements}  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>ThrottleInterval</key>\n  <integer>2</integer>\n  <key>ProcessType</key>\n  <string>Background</string>\n  <key>StandardOutPath</key>\n  <string>{standard_output}</string>\n  <key>StandardErrorPath</key>\n  <string>{standard_error}</string>\n  <key>Umask</key>\n  <integer>63</integer>\n</dict>\n</plist>\n"
    )
    .into_bytes();
    CoreServiceDefinition::new(
        command.process(),
        command.service_identity(),
        format!("{}.plist", command.service_identity()),
        bytes,
        None,
        command.executable().to_path_buf(),
        command.arguments().to_vec(),
    )
}

// Returns the stable user-facing description for one resident role.
const fn process_description(process: CoreResidentProcess) -> &'static str {
    match process {
        CoreResidentProcess::Node => "Let's Infer Node",
        CoreResidentProcess::Gateway => "Let's Infer Gateway",
        CoreResidentProcess::Watchdog => "Let's Infer Watchdog",
    }
}

// Returns the minimum socket families required by one resident process contract.
const fn process_address_families(process: CoreResidentProcess) -> &'static str {
    match process {
        CoreResidentProcess::Node => "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        CoreResidentProcess::Gateway | CoreResidentProcess::Watchdog => "AF_UNIX AF_INET AF_INET6",
    }
}

// Returns the legacy envelope retained provisionally until release Rust binaries are measured.
const fn systemd_process_profile(process: CoreResidentProcess) -> SystemdProcessProfile {
    match process {
        CoreResidentProcess::Node => SystemdProcessProfile {
            memory_high_bytes: 128 * 1024 * 1024,
            memory_max_bytes: 192 * 1024 * 1024,
            restart_seconds: 2,
            stop_timeout_seconds: 15,
            additional_directives: "TasksMax=32\nLimitNOFILE=128\n",
        },
        CoreResidentProcess::Gateway => SystemdProcessProfile {
            memory_high_bytes: 64 * 1024 * 1024,
            memory_max_bytes: 96 * 1024 * 1024,
            restart_seconds: 2,
            stop_timeout_seconds: 30,
            additional_directives: "",
        },
        CoreResidentProcess::Watchdog => SystemdProcessProfile {
            memory_high_bytes: 24 * 1024 * 1024,
            memory_max_bytes: 30 * 1024 * 1024,
            restart_seconds: 5,
            stop_timeout_seconds: 30,
            additional_directives: "TasksMax=8\nLimitNOFILE=64\nNice=10\nCPUWeight=1\nIOWeight=1\nIOSchedulingClass=idle\n",
        },
    }
}

// Quotes one systemd executable argument while escaping specifiers and controls.
fn systemd_argument(value: &std::ffi::OsStr) -> Result<String, CoreServiceDefinitionError> {
    let value = value
        .to_str()
        .ok_or(CoreServiceDefinitionError::UnsafeArgument)?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(CoreServiceDefinitionError::UnsafeArgument);
    }
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '%' => escaped.push_str("%%"),
            _ => escaped.push(character),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

// Converts one path or argument into escaped XML text without accepting controls.
fn xml_argument(value: &std::ffi::OsStr) -> Result<String, CoreServiceDefinitionError> {
    value
        .to_str()
        .ok_or(CoreServiceDefinitionError::UnsafeArgument)
        .and_then(xml_text)
}

// Escapes one nonempty XML text value without permitting control characters.
fn xml_text(value: &str) -> Result<String, CoreServiceDefinitionError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(CoreServiceDefinitionError::UnsafeArgument);
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    Ok(escaped)
}
