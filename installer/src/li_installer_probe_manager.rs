// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::li_installer_arguments::InstallerArguments;
use crate::li_installer_dependency_manager::github_cli_version_is_supported;
use crate::li_installer_linux_provider;
use crate::li_installer_macos_provider;
use crate::{INSTALLATION_PROBE_SCHEMA_NAME, INSTALLATION_PROBE_SCHEMA_VERSION};

// Stores one validated native platform observation and its durable temporary path.
pub struct ProbeFacts {
    document: Value,
    path: PathBuf,
}

impl ProbeFacts {
    // Returns the exact probe document consumed by later lifecycle managers.
    pub fn document(&self) -> &Value {
        &self.document
    }

    // Returns the immutable temporary path consumed by the dependency manager.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // Returns one observed executable dependency when it is available.
    pub fn dependency_path(&self, name: &str) -> Option<PathBuf> {
        self.document
            .pointer(&format!("/dependencies/{}/path", name))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    // Returns the exact readiness status represented by this observation.
    pub fn status(&self) -> Option<&str> {
        self.document.get("status").and_then(Value::as_str)
    }

    // Creates one injected observation for tests that exercise later installer ownership.
    #[cfg(test)]
    pub(crate) fn from_test_document(document: Value) -> Self {
        Self {
            document,
            path: PathBuf::new(),
        }
    }
}

// Owns native dependency discovery and platform-provider composition.
pub struct ProbeManager {
    curl_command: PathBuf,
    id_command: PathBuf,
    macos_helper: Option<PathBuf>,
    platform: String,
    schema_file: PathBuf,
    tar_command: PathBuf,
    temporary_root: PathBuf,
}

impl ProbeManager {
    // Creates a probe manager and verifies the selected archive matches this binary.
    pub fn new(arguments: &InstallerArguments) -> Result<Self, String> {
        let observed_operating_system = match env::consts::OS {
            "linux" => "linux",
            "macos" => "macos",
            value => return Err(format!("native operating system is unsupported: {}", value)),
        };
        let observed_architecture = match env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "x86_64",
            value => return Err(format!("native architecture is unsupported: {}", value)),
        };
        let observed_platform = format!("{}-{}", observed_operating_system, observed_architecture);
        if observed_platform != arguments.selected_platform {
            return Err(format!(
                "selected archive {} does not match native platform {}",
                arguments.selected_platform, observed_platform
            ));
        }
        let executable = env::current_exe()
            .map_err(|error| format!("cannot resolve native installer: {}", error))?;
        let binary_root = executable
            .parent()
            .ok_or_else(|| "native installer has no binary root".to_string())?;
        let install_root = binary_root
            .parent()
            .ok_or_else(|| "native installer has no archive root".to_string())?;
        let schema_file = install_root
            .join("schemas")
            .join("li_installer_installation_probe_v1.schema.json");
        validate_regular_file(&schema_file, "installation-probe schema")?;
        let macos_helper = if observed_operating_system == "macos" {
            let helper = binary_root.join("li_installer_macos_probe");
            validate_executable(&helper, "macOS probe")?;
            Some(helper)
        } else {
            None
        };
        Ok(Self {
            curl_command: arguments.curl_command.clone(),
            id_command: arguments.id_command.clone(),
            macos_helper,
            platform: observed_platform,
            schema_file,
            tar_command: arguments.tar_command.clone(),
            temporary_root: arguments.temporary_root.clone(),
        })
    }

    // Collects, validates, and persists one named native observation.
    pub fn observe(&self, name: &str) -> Result<ProbeFacts, String> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err("probe observation name is invalid".to_string());
        }
        let composition = self.composition()?;
        let provider_arguments = composition.arguments(&self.schema_file)?;
        let document = if self.platform.starts_with("linux-") {
            li_installer_linux_provider::observe(&provider_arguments)?
        } else {
            li_installer_macos_provider::observe(
                self.macos_helper
                    .as_deref()
                    .ok_or_else(|| "macOS probe is unavailable".to_string())?,
                &provider_arguments,
            )?
        };
        let value: Value = serde_json::from_str(&document)
            .map_err(|error| format!("installation probe JSON is invalid: {}", error))?;
        validate_probe_document(&value, &self.platform)?;
        let path = self
            .temporary_root
            .join(format!("li_installer_probe_{}.json", name));
        if path.exists() || path.is_symlink() {
            return Err(format!("probe output already exists: {}", path.display()));
        }
        fs::write(&path, document.as_bytes())
            .map_err(|error| format!("cannot persist installation probe: {}", error))?;
        Ok(ProbeFacts {
            document: value,
            path,
        })
    }

    // Returns the injected identity command used by the dependency manager.
    pub fn id_command(&self) -> &Path {
        &self.id_command
    }

    // Resolves every current native dependency and service-manager fact.
    fn composition(&self) -> Result<ProbeComposition, String> {
        let mut dependencies = BTreeMap::new();
        dependencies.insert("curl".to_string(), self.curl_command.clone());
        dependencies.insert(
            "gh".to_string(),
            command_path_if_available("gh").unwrap_or_default(),
        );
        dependencies.insert(
            "mktemp".to_string(),
            command_path_if_available("mktemp").unwrap_or_default(),
        );
        dependencies.insert(
            "openssl".to_string(),
            command_path_if_available("openssl").unwrap_or_default(),
        );
        dependencies.insert(
            "ssh".to_string(),
            command_path_if_available("ssh").unwrap_or_default(),
        );
        dependencies.insert(
            "ssh_keygen".to_string(),
            command_path_if_available("ssh-keygen").unwrap_or_default(),
        );
        dependencies.insert(
            "sudo".to_string(),
            command_path_if_available("sudo").unwrap_or_default(),
        );
        dependencies.insert("tar".to_string(), self.tar_command.clone());

        let mut missing = Vec::new();
        for name in ["curl", "mktemp", "openssl", "ssh", "ssh_keygen", "tar"] {
            if dependencies[name].as_os_str().is_empty() {
                missing.push(name.to_string());
            }
        }
        let (service_manager, installable) = if self.platform.starts_with("linux-") {
            self.collect_linux_dependencies(&mut dependencies, &mut missing)?
        } else {
            self.collect_macos_dependencies(&mut dependencies, &mut missing)?
        };
        let status = if !missing.is_empty() {
            "missing_dependencies"
        } else if !service_manager.user_domain_available || !service_manager.persistence_available {
            "service_manager_unavailable"
        } else {
            "ready"
        };
        Ok(ProbeComposition {
            dependencies,
            installable,
            missing,
            platform: self.platform.clone(),
            service_manager,
            status: status.to_string(),
        })
    }

    // Collects Linux commands, user systemd reachability, and exact lingering.
    fn collect_linux_dependencies(
        &self,
        dependencies: &mut BTreeMap<String, PathBuf>,
        missing: &mut Vec<String>,
    ) -> Result<(ServiceManagerFacts, BTreeSet<String>), String> {
        for name in [
            "apt_get",
            "avahi_browse",
            "dnf",
            "docker",
            "nvidia_ctk",
            "nvidia_smi",
            "pacman",
            "sg",
            "stat",
            "zypper",
        ] {
            let command = name.replace('_', "-");
            dependencies.insert(
                name.to_string(),
                command_path_if_available(&command).unwrap_or_default(),
            );
        }
        dependencies.insert(
            "avahi_publish_service".to_string(),
            command_entry_path_if_available("avahi-publish-service").unwrap_or_default(),
        );
        let github_cli_is_supported = if dependencies["gh"].as_os_str().is_empty() {
            false
        } else {
            command_output(&dependencies["gh"], &["--version"])
                .ok()
                .is_some_and(|value| github_cli_version_is_supported(&value))
        };
        if !github_cli_is_supported {
            missing.push("gh".to_string());
        }
        let install = command_path_if_available("install").unwrap_or_default();
        if install.as_os_str().is_empty() {
            missing.push("install".to_string());
        }
        dependencies.insert("install".to_string(), install);
        let systemctl = command_path_if_available("systemctl").unwrap_or_default();
        let user_domain_available = !systemctl.as_os_str().is_empty()
            && command_success(&systemctl, &["--user", "show-environment"]);
        dependencies.insert(
            "systemctl".to_string(),
            if user_domain_available {
                systemctl
            } else {
                PathBuf::new()
            },
        );
        if !user_domain_available {
            missing.push("systemctl".to_string());
        }
        let loginctl = command_path_if_available("loginctl").unwrap_or_default();
        let user = command_output(&self.id_command, &["-un"]).unwrap_or_default();
        let linger = if loginctl.as_os_str().is_empty() || user.is_empty() {
            None
        } else {
            command_output(
                &loginctl,
                &["show-user", &user, "--property", "Linger", "--value"],
            )
            .ok()
        };
        let persistence_available = linger.as_deref() == Some("yes");
        dependencies.insert("loginctl".to_string(), loginctl.clone());
        if loginctl.as_os_str().is_empty() || !matches!(linger.as_deref(), Some("yes" | "no")) {
            missing.push("loginctl".to_string());
        }
        let systemd_run = command_path_if_available("systemd-run").unwrap_or_default();
        if systemd_run.as_os_str().is_empty() {
            missing.push("systemd_run".to_string());
        }
        dependencies.insert("systemd_run".to_string(), systemd_run);
        let installable = BTreeSet::from([
            "avahi_browse".to_string(),
            "avahi_publish_service".to_string(),
            "docker".to_string(),
            "gh".to_string(),
            "nvidia_ctk".to_string(),
            "openssl".to_string(),
            "ssh".to_string(),
        ]);
        Ok((
            ServiceManagerFacts {
                persistence_available,
                persistence_mechanism: "systemd-linger".to_string(),
                provider: "systemd".to_string(),
                scope: "user".to_string(),
                user_domain_available,
            },
            installable,
        ))
    }

    // Collects macOS commands and the active graphical launchd user domain.
    fn collect_macos_dependencies(
        &self,
        dependencies: &mut BTreeMap<String, PathBuf>,
        missing: &mut Vec<String>,
    ) -> Result<(ServiceManagerFacts, BTreeSet<String>), String> {
        for name in ["brew", "launchctl", "sw_vers", "sysctl", "system_profiler"] {
            dependencies.insert(
                name.to_string(),
                command_path_if_available(name).unwrap_or_default(),
            );
        }
        let launchctl = dependencies["launchctl"].clone();
        let user_id = command_output(&self.id_command, &["-u"]).unwrap_or_default();
        let expected_user_id = format!("{user_id}\n");
        let user_domain_available = !launchctl.as_os_str().is_empty()
            && !user_id.is_empty()
            && command_exact_output(&launchctl, &["manageruid"], expected_user_id.as_bytes())
            && command_exact_output(&launchctl, &["managername"], b"Aqua\n");
        if !user_domain_available {
            dependencies.insert("launchctl".to_string(), PathBuf::new());
            missing.push("launchctl".to_string());
        }
        for name in ["sw_vers", "sysctl", "system_profiler"] {
            if dependencies[name].as_os_str().is_empty() {
                missing.push(name.to_string());
            }
        }
        Ok((
            ServiceManagerFacts {
                persistence_available: user_domain_available,
                persistence_mechanism: "launch-agent".to_string(),
                provider: "launchd".to_string(),
                scope: "gui".to_string(),
                user_domain_available,
            },
            BTreeSet::from(["openssl".to_string()]),
        ))
    }
}

// Stores the normalized service-manager readiness passed to a provider.
struct ServiceManagerFacts {
    persistence_available: bool,
    persistence_mechanism: String,
    provider: String,
    scope: String,
    user_domain_available: bool,
}

// Stores the complete explicit argument composition for one provider call.
struct ProbeComposition {
    dependencies: BTreeMap<String, PathBuf>,
    installable: BTreeSet<String>,
    missing: Vec<String>,
    platform: String,
    service_manager: ServiceManagerFacts,
    status: String,
}

impl ProbeComposition {
    // Returns the exact named argument vector accepted by both native providers.
    fn arguments(&self, schema_file: &Path) -> Result<Vec<String>, String> {
        let mut arguments = Vec::new();
        push_argument(&mut arguments, "platform", &self.platform);
        push_argument(&mut arguments, "mode", "live");
        push_argument(
            &mut arguments,
            "schema-file",
            &schema_file.to_string_lossy(),
        );
        push_argument(&mut arguments, "status", &self.status);
        push_argument(
            &mut arguments,
            "missing-dependencies",
            &self.missing.join(","),
        );
        push_argument(
            &mut arguments,
            "service-manager-provider",
            &self.service_manager.provider,
        );
        push_argument(
            &mut arguments,
            "service-manager-scope",
            &self.service_manager.scope,
        );
        push_argument(
            &mut arguments,
            "service-manager-user-domain-available",
            boolean_value(self.service_manager.user_domain_available),
        );
        push_argument(
            &mut arguments,
            "service-persistence-mechanism",
            &self.service_manager.persistence_mechanism,
        );
        push_argument(
            &mut arguments,
            "service-persistence-available",
            boolean_value(self.service_manager.persistence_available),
        );
        for (name, path) in &self.dependencies {
            push_argument(
                &mut arguments,
                "dependency",
                &format!("{}={}", name, path.to_string_lossy()),
            );
        }
        for name in &self.installable {
            push_argument(&mut arguments, "installable-dependency", name);
        }
        let date = required_command("date")?;
        let uname = required_command("uname")?;
        push_argument(&mut arguments, "date-command", &date.to_string_lossy());
        push_argument(&mut arguments, "uname-command", &uname.to_string_lossy());
        if self.platform.starts_with("linux-") {
            push_argument(
                &mut arguments,
                "getconf-command",
                &required_command("getconf")?.to_string_lossy(),
            );
            push_argument(&mut arguments, "os-release-file", "/etc/os-release");
            push_argument(&mut arguments, "meminfo-file", "/proc/meminfo");
            push_argument(&mut arguments, "cpuinfo-file", "/proc/cpuinfo");
            push_argument(
                &mut arguments,
                "boot-id-file",
                "/proc/sys/kernel/random/boot_id",
            );
            for (argument, command) in [
                ("lscpu-command", "lscpu"),
                ("nvidia-smi-command", "nvidia-smi"),
                ("docker-command", "docker"),
                ("nvidia-ctk-command", "nvidia-ctk"),
            ] {
                let value = command_path_if_available(command).unwrap_or_default();
                push_argument(&mut arguments, argument, &value.to_string_lossy());
            }
        } else {
            for (argument, command) in [
                ("sysctl-command", "sysctl"),
                ("sw-vers-command", "sw_vers"),
                ("system-profiler-command", "system_profiler"),
            ] {
                push_argument(
                    &mut arguments,
                    argument,
                    &required_command(command)?.to_string_lossy(),
                );
            }
            push_argument(&mut arguments, "metal-observation-source", "native");
            push_argument(&mut arguments, "metal-observation-file", "");
        }
        Ok(arguments)
    }
}

// Appends one exact named value to a native provider argument vector.
fn push_argument(arguments: &mut Vec<String>, name: &str, value: &str) {
    arguments.push(format!("--{}", name));
    arguments.push(value.to_string());
}

// Returns one stable JSON boolean spelling.
fn boolean_value(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

// Returns one required command from the current process search path.
fn required_command(name: &str) -> Result<PathBuf, String> {
    command_path_if_available(name)
        .ok_or_else(|| format!("required command is unavailable: {}", name))
}

// Returns one canonical executable command target from the current process search path.
fn command_path_if_available(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    command_path_in(name, &path)
}

// Returns one executable command entry whose invoked name selects native behavior.
fn command_entry_path_if_available(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    command_entry_path_in(name, &path)
}

// Returns one canonical executable command target from an explicit search path.
fn command_path_in(name: &str, path: &OsStr) -> Option<PathBuf> {
    for root in env::split_paths(&path) {
        let candidate = root.join(name);
        let Ok(resolved) = fs::canonicalize(candidate) else {
            continue;
        };
        if validate_executable(&resolved, name).is_ok() {
            return Some(resolved);
        }
    }
    None
}

// Preserves one final command entry while resolving and validating its executable target.
fn command_entry_path_in(name: &str, path: &OsStr) -> Option<PathBuf> {
    for root in env::split_paths(path) {
        let Ok(root) = fs::canonicalize(root) else {
            continue;
        };
        let entry = root.join(name);
        let Ok(resolved) = fs::canonicalize(&entry) else {
            continue;
        };
        if validate_executable(&resolved, name).is_ok() {
            return Some(entry);
        }
    }
    None
}

// Returns whether one command succeeds with exact shell-free arguments.
fn command_success(command: &Path, arguments: &[&str]) -> bool {
    Command::new(command)
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

// Requires one successful native command to emit only the exact authoritative bytes.
fn command_exact_output(command: &Path, arguments: &[&str], expected: &[u8]) -> bool {
    Command::new(command)
        .args(arguments)
        .output()
        .is_ok_and(|output| {
            exact_native_output_matches(
                output.status.success(),
                &output.stdout,
                &output.stderr,
                expected,
            )
        })
}

// Compares one injected native result without normalization or diagnostic ambiguity.
fn exact_native_output_matches(
    succeeded: bool,
    stdout: &[u8],
    stderr: &[u8],
    expected: &[u8],
) -> bool {
    succeeded && stdout == expected && stderr.is_empty()
}

// Returns bounded trimmed UTF-8 output from one native command.
fn command_output(command: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .map_err(|error| format!("native command could not run: {}", error))?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err("native command failed".to_string());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "native command output is not UTF-8".to_string())
}

// Verifies the minimum schema and platform identity consumed by the installer.
fn validate_probe_document(document: &Value, platform: &str) -> Result<(), String> {
    if document.pointer("/schema/name").and_then(Value::as_str)
        != Some(INSTALLATION_PROBE_SCHEMA_NAME)
        || document.pointer("/schema/version").and_then(Value::as_u64)
            != Some(INSTALLATION_PROBE_SCHEMA_VERSION)
        || document
            .pointer("/platform/identifier")
            .and_then(Value::as_str)
            != Some(platform)
    {
        return Err("installation probe identity is invalid".to_string());
    }
    if !document.get("dependencies").is_some_and(Value::is_object)
        || !document.get("hardware").is_some_and(Value::is_object)
        || !document
            .get("service_manager")
            .is_some_and(Value::is_object)
    {
        return Err("installation probe document is incomplete".to_string());
    }
    Ok(())
}

// Verifies one regular executable file.
fn validate_executable(path: &Path, name: &str) -> Result<(), String> {
    validate_regular_file(path, name)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|error| format!("cannot inspect {}: {}", name, error))?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err(format!("{} is not executable", name));
        }
    }
    Ok(())
}

// Verifies one nonsymlink regular file.
fn validate_regular_file(path: &Path, name: &str) -> Result<(), String> {
    let details = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {}", name, error))?;
    if details.file_type().is_symlink() || !details.is_file() {
        return Err(format!("{} is not a regular file", name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Returns one isolated command-search fixture without sharing process PATH state.
    fn command_fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "li_installer_probe_{name}_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("command fixture root");
        root
    }

    // Writes one direct executable fixture target.
    #[cfg(unix)]
    fn write_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, b"#!/bin/sh\nexit 0\n").expect("command fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("command fixture permissions");
    }

    // Preserves service-mode argv identity while ordinary command search stays canonical.
    #[cfg(unix)]
    #[test]
    fn service_mode_command_search_preserves_executable_symlink_entry() {
        use std::os::unix::fs::symlink;

        let root = command_fixture("command_symlink");
        let executable = root.join("avahi-publish");
        let command = root.join("avahi-publish-service");
        write_executable(&executable);
        symlink(&executable, &command).expect("command fixture symlink");

        assert_eq!(
            command_path_in("avahi-publish-service", root.as_os_str()),
            Some(fs::canonicalize(&executable).expect("canonical fixture target"))
        );
        assert_eq!(
            command_entry_path_in("avahi-publish-service", root.as_os_str()),
            Some(
                fs::canonicalize(&root)
                    .expect("canonical fixture root")
                    .join("avahi-publish-service")
            )
        );

        fs::remove_dir_all(root).expect("remove command fixture");
    }

    // Skips broken and non-executable link targets without accepting an unsafe command path.
    #[cfg(unix)]
    #[test]
    fn command_search_rejects_unusable_symlink_targets() {
        use std::os::unix::fs::symlink;

        let root = command_fixture("unusable_command_symlink");
        let non_executable = root.join("non-executable");
        fs::write(&non_executable, b"not executable\n").expect("command fixture");
        symlink(&non_executable, root.join("linked-command")).expect("command fixture symlink");
        symlink(root.join("absent"), root.join("broken-command"))
            .expect("broken command fixture symlink");

        assert_eq!(command_path_in("linked-command", root.as_os_str()), None);
        assert_eq!(command_path_in("broken-command", root.as_os_str()), None);
        assert_eq!(
            command_entry_path_in("linked-command", root.as_os_str()),
            None
        );
        assert_eq!(
            command_entry_path_in("broken-command", root.as_os_str()),
            None
        );

        fs::remove_dir_all(root).expect("remove command fixture");
    }

    // Accepts only one exact successful raw native identity response.
    #[test]
    fn exact_native_identity_output_is_closed() {
        for (succeeded, stdout, stderr, accepted) in [
            (true, b"501\n".as_slice(), b"".as_slice(), true),
            (false, b"501\n".as_slice(), b"".as_slice(), false),
            (true, b" 501\n".as_slice(), b"".as_slice(), false),
            (true, b"501".as_slice(), b"".as_slice(), false),
            (true, b"501\nextra\n".as_slice(), b"".as_slice(), false),
            (true, &[0xff], b"".as_slice(), false),
            (true, b"501\n".as_slice(), b"diagnostic".as_slice(), false),
        ] {
            assert_eq!(
                exact_native_output_matches(succeeded, stdout, stderr, b"501\n"),
                accepted
            );
        }
    }
}
