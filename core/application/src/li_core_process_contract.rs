// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path, PathBuf};

// Identifies the supported native service-supervision family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreProcessPlatform {
    Linux,
    Macos,
}

// Identifies one independently supervised Rust Core resident process.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoreResidentProcess {
    Node,
    Gateway,
    Watchdog,
}

impl CoreResidentProcess {
    // Returns the immutable project-owned executable filename.
    pub const fn executable_name(self) -> &'static str {
        match self {
            Self::Node => "li_node",
            Self::Gateway => "li_gateway",
            Self::Watchdog => "li_watchdog",
        }
    }

    // Returns the immutable project-owned configuration filename.
    pub const fn configuration_name(self) -> &'static str {
        match self {
            Self::Node => "li_node.json",
            Self::Gateway => "li_gateway.json",
            Self::Watchdog => "li_watchdog.json",
        }
    }

    // Returns the exact Linux user-unit identity.
    pub const fn linux_service_identity(self) -> &'static str {
        match self {
            Self::Node => "li_node.service",
            Self::Gateway => "li_gateway.service",
            Self::Watchdog => "li_watchdog.service",
        }
    }

    // Returns the exact macOS launchd label when this process exists on macOS.
    pub const fn macos_service_identity(self) -> Option<&'static str> {
        match self {
            Self::Node => Some("ai.letsinfer.node"),
            Self::Gateway => Some("ai.letsinfer.gateway"),
            Self::Watchdog => None,
        }
    }
}

// Carries one exact shell-free resident-process invocation and supervisor identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreResidentProcessCommand {
    process: CoreResidentProcess,
    service_identity: &'static str,
    executable: PathBuf,
    arguments: Vec<OsString>,
    configuration: PathBuf,
    standard_output: Option<PathBuf>,
    standard_error: Option<PathBuf>,
}

impl CoreResidentProcessCommand {
    // Returns the independently supervised process role.
    pub const fn process(&self) -> CoreResidentProcess {
        self.process
    }

    // Returns the exact systemd unit or launchd label.
    pub const fn service_identity(&self) -> &'static str {
        self.service_identity
    }

    // Returns the immutable executable selected from one Core installation.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns the fixed shell-free process arguments.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    // Returns the one mutable configuration document owned outside the installation.
    pub fn configuration(&self) -> &Path {
        &self.configuration
    }

    // Returns the exact native standard-output path when the supervisor requires one.
    pub fn standard_output(&self) -> Option<&Path> {
        self.standard_output.as_deref()
    }

    // Returns the exact native standard-error path when the supervisor requires one.
    pub fn standard_error(&self) -> Option<&Path> {
        self.standard_error.as_deref()
    }
}

// Resolves all resident binaries and configurations without inspecting mutable host state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreProcessLayout {
    platform: CoreProcessPlatform,
    installation_root: PathBuf,
    configuration_root: PathBuf,
    log_root: PathBuf,
}

impl CoreProcessLayout {
    // Creates one layout from distinct canonical absolute installation and configuration roots.
    pub fn new(
        platform: CoreProcessPlatform,
        installation_root: PathBuf,
        configuration_root: PathBuf,
        log_root: PathBuf,
    ) -> Result<Self, CoreProcessContractError> {
        require_absolute_normal_path(&installation_root)?;
        require_absolute_normal_path(&configuration_root)?;
        require_absolute_normal_path(&log_root)?;
        if roots_overlap(&installation_root, &configuration_root)
            || roots_overlap(&installation_root, &log_root)
            || roots_overlap(&configuration_root, &log_root)
        {
            return Err(CoreProcessContractError::AmbiguousRoots);
        }
        Ok(Self {
            platform,
            installation_root,
            configuration_root,
            log_root,
        })
    }

    // Returns the native service-supervision family.
    pub const fn platform(&self) -> CoreProcessPlatform {
        self.platform
    }

    // Returns the immutable installation root containing resident binaries.
    pub fn installation_root(&self) -> &Path {
        &self.installation_root
    }

    // Returns the private mutable root containing process configuration documents.
    pub fn configuration_root(&self) -> &Path {
        &self.configuration_root
    }

    // Returns the private mutable root containing resident process logs.
    pub fn log_root(&self) -> &Path {
        &self.log_root
    }

    // Resolves one exact resident invocation without checking the filesystem or starting it.
    pub fn command(
        &self,
        process: CoreResidentProcess,
    ) -> Result<CoreResidentProcessCommand, CoreProcessContractError> {
        let service_identity = match self.platform {
            CoreProcessPlatform::Linux => process.linux_service_identity(),
            CoreProcessPlatform::Macos => process
                .macos_service_identity()
                .ok_or(CoreProcessContractError::UnsupportedProcess)?,
        };
        let executable = self
            .installation_root
            .join("bin")
            .join(process.executable_name());
        let configuration = self.configuration_root.join(process.configuration_name());
        let (standard_output, standard_error) = match self.platform {
            CoreProcessPlatform::Linux => (None, None),
            CoreProcessPlatform::Macos => (
                Some(
                    self.log_root
                        .join(format!("{}.log", process.executable_name())),
                ),
                Some(
                    self.log_root
                        .join(format!("{}.error.log", process.executable_name())),
                ),
            ),
        };
        Ok(CoreResidentProcessCommand {
            process,
            service_identity,
            executable,
            arguments: vec![
                OsString::from("--configuration"),
                configuration.as_os_str().to_os_string(),
            ],
            configuration,
            standard_output,
            standard_error,
        })
    }

    // Returns the complete platform-appropriate resident set in startup order.
    pub fn commands(&self) -> Result<Vec<CoreResidentProcessCommand>, CoreProcessContractError> {
        let processes: &[CoreResidentProcess] = match self.platform {
            CoreProcessPlatform::Linux => &[
                CoreResidentProcess::Node,
                CoreResidentProcess::Watchdog,
                CoreResidentProcess::Gateway,
            ],
            CoreProcessPlatform::Macos => {
                &[CoreResidentProcess::Node, CoreResidentProcess::Gateway]
            }
        };
        processes
            .iter()
            .map(|process| self.command(*process))
            .collect()
    }
}

// Returns whether two already-normalized roots are equal or nested in either direction.
fn roots_overlap(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

// Describes one invalid resident-process layout before any service mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreProcessContractError {
    UnsafePath,
    AmbiguousRoots,
    UnsupportedProcess,
}

impl fmt::Display for CoreProcessContractError {
    // Presents stable path-free process configuration language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath => formatter.write_str("a Core process path is unsafe"),
            Self::AmbiguousRoots => {
                formatter.write_str("Core installation and configuration roots overlap")
            }
            Self::UnsupportedProcess => {
                formatter.write_str("the resident process is unavailable on this platform")
            }
        }
    }
}

impl Error for CoreProcessContractError {}

// Requires one absolute path composed only of a root and ordinary nonempty components.
fn require_absolute_normal_path(path: &Path) -> Result<(), CoreProcessContractError> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(CoreProcessContractError::UnsafePath);
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| match component {
            Component::Normal(value) => value.is_empty() || value == OsStr::new("."),
            _ => true,
        })
    {
        return Err(CoreProcessContractError::UnsafePath);
    }
    Ok(())
}
