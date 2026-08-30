// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

// Selects whether setup observes the default-route address or uses one explicit operator value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControlAddressSelection {
    Automatic,
    Explicit(String),
}

// Stores the complete immutable handoff from the shell bootstrap.
#[derive(Debug)]
pub struct InstallerArguments {
    pub allow_insecure: bool,
    pub checksums_file: PathBuf,
    pub(crate) control_address: ControlAddressSelection,
    pub core_archive_name: String,
    pub curl_command: PathBuf,
    pub id_command: PathBuf,
    pub letsinfer_home: PathBuf,
    pub launcher_root: PathBuf,
    pub progress_enabled: bool,
    pub release_base: String,
    pub release_allowed_signers_file: PathBuf,
    pub release_version: String,
    pub repair_docker_access: bool,
    pub run_setup: bool,
    pub selected_platform: String,
    pub tar_command: PathBuf,
    pub temporary_root: PathBuf,
    pub user_install: bool,
}

impl InstallerArguments {
    // Parses exact name/value pairs and rejects unknown or duplicate arguments.
    pub fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut index = 0;
        while index < arguments.len() {
            let raw_name = &arguments[index];
            let name = raw_name
                .strip_prefix("--")
                .ok_or_else(|| format!("argument name is invalid: {}", raw_name))?;
            if !matches!(
                name,
                "allow-insecure"
                    | "checksums-file"
                    | "control-address"
                    | "core-archive-name"
                    | "curl-command"
                    | "id-command"
                    | "letsinfer-home"
                    | "launcher-root"
                    | "progress-enabled"
                    | "release-base"
                    | "release-allowed-signers-file"
                    | "release-version"
                    | "repair-docker-access"
                    | "run-setup"
                    | "selected-platform"
                    | "tar-command"
                    | "temporary-root"
                    | "user-install"
            ) {
                return Err(format!("unknown argument: {}", raw_name));
            }
            if values.contains_key(name) {
                return Err(format!("duplicate argument: {}", raw_name));
            }
            index += 1;
            let value = arguments
                .get(index)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("argument requires a value: {}", raw_name))?;
            values.insert(name.to_string(), value.clone());
            index += 1;
        }

        let parsed = Self {
            allow_insecure: required_boolean(&values, "allow-insecure")?,
            checksums_file: required_path(&values, "checksums-file")?,
            control_address: control_address_selection(values.get("control-address"))?,
            core_archive_name: required_value(&values, "core-archive-name")?.to_string(),
            curl_command: required_path(&values, "curl-command")?,
            id_command: required_path(&values, "id-command")?,
            letsinfer_home: required_path(&values, "letsinfer-home")?,
            launcher_root: required_path(&values, "launcher-root")?,
            progress_enabled: required_boolean(&values, "progress-enabled")?,
            release_base: required_value(&values, "release-base")?.to_string(),
            release_allowed_signers_file: required_path(&values, "release-allowed-signers-file")?,
            release_version: required_value(&values, "release-version")?.to_string(),
            repair_docker_access: required_boolean(&values, "repair-docker-access")?,
            run_setup: required_boolean(&values, "run-setup")?,
            selected_platform: required_value(&values, "selected-platform")?.to_string(),
            tar_command: required_path(&values, "tar-command")?,
            temporary_root: required_path(&values, "temporary-root")?,
            user_install: required_boolean(&values, "user-install")?,
        };
        parsed.validate()?;
        Ok(parsed)
    }

    // Returns the canonical operating system represented by the selected archive.
    pub fn operating_system(&self) -> &'static str {
        if self.selected_platform.starts_with("linux-") {
            "linux"
        } else {
            "macos"
        }
    }

    // Returns the canonical architecture represented by the selected archive.
    pub fn architecture(&self) -> &'static str {
        if self.selected_platform.ends_with("-arm64") {
            "arm64"
        } else {
            "x86_64"
        }
    }

    // Verifies paths, platform identity, and release names before native work.
    fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.selected_platform.as_str(),
            "linux-arm64" | "linux-x86_64" | "macos-arm64"
        ) {
            return Err(format!(
                "selected installer platform is unsupported: {}",
                self.selected_platform
            ));
        }
        let expected_archive = format!(
            "letsinfer-{}-{}.tar.gz",
            self.operating_system(),
            self.architecture()
        );
        if self.core_archive_name != expected_archive {
            return Err("Core archive does not match selected platform".to_string());
        }
        for (name, path) in [
            ("curl command", &self.curl_command),
            ("identity command", &self.id_command),
            ("tar command", &self.tar_command),
        ] {
            validate_executable(path, name)?;
        }
        validate_regular_file(&self.checksums_file, "signed checksums")?;
        validate_regular_file(
            &self.release_allowed_signers_file,
            "release allowed signers",
        )?;
        let temporary = self.temporary_root.to_string_lossy();
        if !temporary.starts_with("/tmp/letsinfer-install.") {
            return Err("temporary installation root is unsafe".to_string());
        }
        if !self.temporary_root.is_dir() || self.temporary_root.is_symlink() {
            return Err("temporary installation root is unavailable".to_string());
        }
        if !self.letsinfer_home.is_absolute() || !self.launcher_root.is_absolute() {
            return Err("installation paths must be absolute".to_string());
        }
        if self.release_version.contains('\n') || self.release_version.contains('\0') {
            return Err("release version is invalid".to_string());
        }
        Ok(())
    }
}

// Normalizes the optional public address selection without resolving hostnames or routes.
fn control_address_selection(value: Option<&String>) -> Result<ControlAddressSelection, String> {
    let Some(value) = value.map(String::as_str) else {
        return Ok(ControlAddressSelection::Automatic);
    };
    if value == "auto" {
        return Ok(ControlAddressSelection::Automatic);
    }
    if value.is_empty() || value.len() > 253 || value.chars().any(char::is_whitespace) {
        return Err("control address is invalid".to_string());
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return match address {
            IpAddr::V4(address)
                if !address.is_loopback()
                    && !address.is_unspecified()
                    && !address.is_multicast() =>
            {
                Ok(ControlAddressSelection::Explicit(address.to_string()))
            }
            _ => Err("control address must be a routable IPv4 address".to_string()),
        };
    }
    let normalized = value.to_ascii_lowercase();
    let valid = normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if !valid || normalized == "localhost" {
        return Err("control address is invalid".to_string());
    }
    Ok(ControlAddressSelection::Explicit(normalized))
}

// Returns one required parsed value without inventing a default.
fn required_value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("required argument is missing: --{}", name))
}

// Returns one required absolute path from a parsed argument.
fn required_path(values: &BTreeMap<String, String>, name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(required_value(values, name)?);
    if !path.is_absolute() {
        return Err(format!("argument path must be absolute: --{}", name));
    }
    Ok(path)
}

// Returns one required boolean without accepting alternate spellings.
fn required_boolean(values: &BTreeMap<String, String>, name: &str) -> Result<bool, String> {
    match required_value(values, name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("boolean argument is invalid: --{}", name)),
    }
}

// Verifies one absolute executable supplied by the shell bootstrap.
fn validate_executable(path: &Path, name: &str) -> Result<(), String> {
    let details =
        fs::metadata(path).map_err(|error| format!("cannot inspect {}: {}", name, error))?;
    if !details.is_file() {
        return Err(format!(
            "{} is not a regular file: {}",
            name,
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = details.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(format!("{} is not executable: {}", name, path.display()));
        }
    }
    Ok(())
}

// Verifies one absolute nonsymlink regular file.
fn validate_regular_file(path: &Path, name: &str) -> Result<(), String> {
    let details = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {}", name, error))?;
    if details.file_type().is_symlink() || !details.is_file() {
        return Err(format!(
            "{} is not a regular file: {}",
            name,
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves automatic and explicit control addresses normalize without accepting local listeners.
    #[test]
    fn control_address_selection_is_closed_and_canonical() {
        assert_eq!(
            control_address_selection(None).expect("default"),
            ControlAddressSelection::Automatic
        );
        assert_eq!(
            control_address_selection(Some(&"auto".to_string())).expect("automatic"),
            ControlAddressSelection::Automatic
        );
        assert_eq!(
            control_address_selection(Some(&"HomeAI.Local".to_string())).expect("hostname"),
            ControlAddressSelection::Explicit("homeai.local".to_string())
        );
        assert_eq!(
            control_address_selection(Some(&"192.168.1.66".to_string())).expect("IPv4"),
            ControlAddressSelection::Explicit("192.168.1.66".to_string())
        );
        for invalid in [
            "",
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "bad host",
            "-host.local",
            "host-.local",
            "host..local",
        ] {
            assert!(
                control_address_selection(Some(&invalid.to_string())).is_err(),
                "{invalid}"
            );
        }
    }

    // Rejects an incomplete shell-to-native handoff before any host mutation.
    #[test]
    fn rejects_incomplete_handoff() {
        let arguments = vec![
            "--selected-platform".to_string(),
            "macos-x86_64".to_string(),
        ];
        assert!(InstallerArguments::parse(&arguments).is_err());
    }
}
