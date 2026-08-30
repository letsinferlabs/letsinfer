// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::{INSTALLATION_PROBE_SCHEMA_NAME, INSTALLATION_PROBE_SCHEMA_VERSION};

const MAXIMUM_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_JSON_DEPTH: usize = 64;
const GITHUB_CLI_MINIMUM_VERSION: (u64, u64, u64) = (2, 97, 0);
const GITHUB_CLI_KEYRING_URL: &str =
    "https://cli.github.com/packages/githubcli-archive-keyring.gpg";
const GITHUB_CLI_KEYRING_SHA256: &str =
    "6084d5d7bd8e288441e0e94fc6275570895da18e6751f70f057485dc2d1a811b";
const GITHUB_CLI_KEYRING_PATH: &str = "/etc/apt/keyrings/githubcli-archive-keyring.gpg";
const GITHUB_CLI_SOURCE_DIRECTORY: &str = "/etc/apt/sources.list.d";
const GITHUB_CLI_SOURCE_PATH: &str = "/etc/apt/sources.list.d/github-cli.list";

// Stores one bounded native command result without exposing process handles.
#[derive(Debug)]
struct NativeCommandOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

// Isolates every filesystem and process action used by dependency installation.
trait NativeActions {
    // Reads one bounded regular file through the active native provider.
    fn read_file(&mut self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, String>;

    // Creates one new private temporary file without following an existing path.
    fn write_new_file(&mut self, path: &Path, contents: &[u8]) -> Result<(), String>;

    // Removes one exact temporary file when it exists.
    fn remove_file_if_present(&mut self, path: &Path) -> Result<(), String>;

    // Verifies one injected executable before it reaches the process boundary.
    fn validate_executable(&mut self, path: &Path) -> Result<(), String>;

    // Runs one injected native command without a shell.
    fn run_command(
        &mut self,
        command: &Path,
        arguments: &[String],
        environment: &[(&str, &str)],
    ) -> Result<NativeCommandOutput, String>;
}

// Performs production dependency actions against the local operating system.
struct SystemNativeActions;

impl NativeActions for SystemNativeActions {
    // Reads one nonsymlink regular file within an explicit byte boundary.
    fn read_file(&mut self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {}", path.display(), error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() as usize > maximum_bytes
        {
            return Err(format!(
                "input is not a bounded regular file: {}",
                path.display()
            ));
        }
        fs::read(path).map_err(|error| format!("cannot read {}: {}", path.display(), error))
    }

    // Creates one owner-only temporary file and writes its complete contents.
    fn write_new_file(&mut self, path: &Path, contents: &[u8]) -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|error| format!("cannot create {}: {}", path.display(), error))?;
        file.write_all(contents)
            .map_err(|error| format!("cannot write {}: {}", path.display(), error))?;
        file.sync_all()
            .map_err(|error| format!("cannot synchronize {}: {}", path.display(), error))
    }

    // Removes one exact temporary file and accepts an already-absent path.
    fn remove_file_if_present(&mut self, path: &Path) -> Result<(), String> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot remove {}: {}", path.display(), error)),
        }
    }

    // Verifies one nonsymlink absolute regular executable.
    fn validate_executable(&mut self, path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err(format!("command path is not absolute: {}", path.display()));
        }
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!("cannot inspect command path {}: {}", path.display(), error)
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "command path is not a regular file: {}",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!(
                    "command path is not executable: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    // Runs one bounded command with only explicitly supplied environment overrides.
    fn run_command(
        &mut self,
        command: &Path,
        arguments: &[String],
        environment: &[(&str, &str)],
    ) -> Result<NativeCommandOutput, String> {
        let output = Command::new(command)
            .args(arguments)
            .envs(environment.iter().copied())
            .output()
            .map_err(|error| format!("native command could not run: {}", error))?;
        validate_command_output_size(&output.stdout, &output.stderr)?;
        Ok(NativeCommandOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

// Represents the bounded JSON values consumed from an installation probe.
#[derive(Debug)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    // Returns this value as an object when its JSON type agrees.
    fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(value) => Some(value),
            _ => None,
        }
    }

    // Returns this value as an array when its JSON type agrees.
    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(value) => Some(value),
            _ => None,
        }
    }

    // Returns this value as a string when its JSON type agrees.
    fn as_string(&self) -> Option<&str> {
        match self {
            JsonValue::String(value) => Some(value),
            _ => None,
        }
    }

    // Returns this value as a boolean when its JSON type agrees.
    fn as_boolean(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(value) => Some(*value),
            _ => None,
        }
    }

    // Returns this value as its exact JSON number representation.
    fn as_number(&self) -> Option<&str> {
        match self {
            JsonValue::Number(value) => Some(value),
            _ => None,
        }
    }
}

// Parses one bounded JSON document without requiring a runtime library.
struct JsonParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> JsonParser<'a> {
    // Creates a parser over one immutable UTF-8 document.
    fn new(document: &'a str) -> Self {
        Self {
            bytes: document.as_bytes(),
            index: 0,
        }
    }

    // Parses exactly one JSON value and rejects trailing content.
    fn parse(mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        if self.index != self.bytes.len() {
            return Err("installation probe contains trailing JSON content".to_string());
        }
        Ok(value)
    }

    // Parses one JSON value while enforcing the nesting boundary.
    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAXIMUM_JSON_DEPTH {
            return Err("installation probe JSON is nested too deeply".to_string());
        }
        self.skip_whitespace();
        match self.peek_byte() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            _ => Err("installation probe contains an invalid JSON value".to_string()),
        }
    }

    // Parses one JSON object and rejects duplicate member names.
    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        let mut values = BTreeMap::new();
        if self.consume_byte_if_present(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.skip_whitespace();
            let name = self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            let value = self.parse_value(depth)?;
            if values.insert(name.clone(), value).is_some() {
                return Err(format!("installation probe repeats JSON member: {}", name));
            }
            self.skip_whitespace();
            if self.consume_byte_if_present(b'}') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Object(values))
    }

    // Parses one JSON array with the shared nesting boundary.
    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume_byte_if_present(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            if self.consume_byte_if_present(b']') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    // Parses one JSON string including escaped Unicode scalar values.
    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"')?;
        let mut output = String::new();
        let mut segment_start = self.index;
        loop {
            let byte = self
                .peek_byte()
                .ok_or_else(|| "installation probe contains an unterminated string".to_string())?;
            match byte {
                b'"' => {
                    self.append_utf8_segment(&mut output, segment_start, self.index)?;
                    self.index += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.append_utf8_segment(&mut output, segment_start, self.index)?;
                    self.index += 1;
                    self.parse_string_escape(&mut output)?;
                    segment_start = self.index;
                }
                0x00..=0x1f => {
                    return Err(
                        "installation probe contains a control character in a string".to_string(),
                    );
                }
                _ => self.index += 1,
            }
        }
    }

    // Appends one verified UTF-8 segment to a decoded JSON string.
    fn append_utf8_segment(
        &self,
        output: &mut String,
        start: usize,
        end: usize,
    ) -> Result<(), String> {
        let segment = std::str::from_utf8(&self.bytes[start..end])
            .map_err(|_| "installation probe contains invalid UTF-8".to_string())?;
        output.push_str(segment);
        Ok(())
    }

    // Decodes one JSON string escape into its canonical scalar value.
    fn parse_string_escape(&mut self, output: &mut String) -> Result<(), String> {
        let escaped = self
            .next_byte()
            .ok_or_else(|| "installation probe contains an incomplete string escape".to_string())?;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => output.push(self.parse_unicode_scalar()?),
            _ => return Err("installation probe contains an invalid string escape".to_string()),
        }
        Ok(())
    }

    // Decodes one JSON Unicode escape and its optional surrogate pair.
    fn parse_unicode_scalar(&mut self) -> Result<char, String> {
        let leading = self.parse_hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&leading) {
            self.expect_byte(b'\\')?;
            self.expect_byte(b'u')?;
            let trailing = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&trailing) {
                return Err("installation probe contains an invalid Unicode surrogate".to_string());
            }
            0x10000 + (((leading - 0xd800) as u32) << 10) + (trailing - 0xdc00) as u32
        } else if (0xdc00..=0xdfff).contains(&leading) {
            return Err("installation probe contains an unexpected Unicode surrogate".to_string());
        } else {
            leading as u32
        };
        char::from_u32(scalar)
            .ok_or_else(|| "installation probe contains an invalid Unicode scalar".to_string())
    }

    // Parses exactly four hexadecimal digits from one Unicode escape.
    fn parse_hex_quad(&mut self) -> Result<u16, String> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let byte = self.next_byte().ok_or_else(|| {
                "installation probe contains an incomplete Unicode escape".to_string()
            })?;
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u16,
                b'a'..=b'f' => (byte - b'a' + 10) as u16,
                b'A'..=b'F' => (byte - b'A' + 10) as u16,
                _ => {
                    return Err("installation probe contains an invalid Unicode escape".to_string());
                }
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    // Parses one syntactically valid JSON number without changing its identity.
    fn parse_number(&mut self) -> Result<String, String> {
        let start = self.index;
        self.consume_byte_if_present(b'-');
        match self.peek_byte() {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.index += 1;
                self.consume_ascii_digits();
            }
            _ => return Err("installation probe contains an invalid JSON number".to_string()),
        }
        if self.consume_byte_if_present(b'.') {
            let fraction_start = self.index;
            self.consume_ascii_digits();
            if fraction_start == self.index {
                return Err("installation probe contains an invalid JSON fraction".to_string());
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            let exponent_start = self.index;
            self.consume_ascii_digits();
            if exponent_start == self.index {
                return Err("installation probe contains an invalid JSON exponent".to_string());
            }
        }
        std::str::from_utf8(&self.bytes[start..self.index])
            .map(str::to_string)
            .map_err(|_| "installation probe number is not UTF-8".to_string())
    }

    // Advances over every immediately available ASCII digit.
    fn consume_ascii_digits(&mut self) {
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
    }

    // Advances over one exact JSON literal.
    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        let end = self.index.saturating_add(literal.len());
        if self.bytes.get(self.index..end) != Some(literal) {
            return Err("installation probe contains an invalid JSON literal".to_string());
        }
        self.index = end;
        Ok(())
    }

    // Advances over JSON whitespace without accepting other separators.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    // Consumes one expected byte or returns a stable syntax failure.
    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        match self.next_byte() {
            Some(value) if value == expected => Ok(()),
            _ => Err("installation probe contains invalid JSON punctuation".to_string()),
        }
    }

    // Consumes one byte only when it matches the requested value.
    fn consume_byte_if_present(&mut self, expected: u8) -> bool {
        if self.peek_byte() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    // Returns the current byte without changing parser state.
    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    // Returns the current byte and advances parser state once.
    fn next_byte(&mut self) -> Option<u8> {
        let value = self.peek_byte()?;
        self.index += 1;
        Some(value)
    }
}

// Represents one observed dependency and its installation policy.
#[derive(Debug)]
struct DependencyObservation {
    version: String,
    path: String,
    installable: bool,
}

// Represents the observed user-service domain and persistence boundary.
#[derive(Debug)]
struct ServiceManagerObservation {
    provider: String,
    scope: String,
    persistence_mechanism: String,
    user_domain_available: bool,
    persistence_available: bool,
}

// Stores the exact installation facts needed by the dependency manager.
#[derive(Debug)]
struct ProbeDocument {
    platform: String,
    distribution: String,
    service_manager: ServiceManagerObservation,
    dependencies: BTreeMap<String, DependencyObservation>,
    required_missing_dependencies: BTreeSet<String>,
}

// Represents the only two supported dependency-manager lifecycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerMode {
    Apply,
    Verify,
}

// Represents one completed dependency-manager lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyManagerResult {
    Installed,
    Unchanged,
}

// Stores every native construct supplied by the composition root.
struct ManagerArguments {
    mode: ManagerMode,
    probe_file: PathBuf,
    id_command: PathBuf,
}

// Stores the immutable GitHub CLI repository trust and destination contract.
struct GitHubCliRepository<'a> {
    keyring_url: &'a str,
    keyring_sha256: &'a str,
    keyring_path: &'a str,
    source_directory: &'a str,
    source_path: &'a str,
}

impl GitHubCliRepository<'static> {
    // Returns the pinned production repository contract.
    fn production() -> Self {
        Self {
            keyring_url: GITHUB_CLI_KEYRING_URL,
            keyring_sha256: GITHUB_CLI_KEYRING_SHA256,
            keyring_path: GITHUB_CLI_KEYRING_PATH,
            source_directory: GITHUB_CLI_SOURCE_DIRECTORY,
            source_path: GITHUB_CLI_SOURCE_PATH,
        }
    }
}

// Represents one native package manager selected from observed platform facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageManager {
    AptGet,
    Brew,
    Dnf,
    Pacman,
    Zypper,
}

impl PackageManager {
    // Returns the dependency key carrying this package manager's executable.
    fn dependency_name(self) -> &'static str {
        match self {
            PackageManager::AptGet => "apt_get",
            PackageManager::Brew => "brew",
            PackageManager::Dnf => "dnf",
            PackageManager::Pacman => "pacman",
            PackageManager::Zypper => "zypper",
        }
    }

    // Returns the native package providing one installable dependency.
    fn package_name(self, dependency: &str) -> Option<&'static str> {
        match (self, dependency) {
            (PackageManager::AptGet, "avahi_browse") => Some("avahi-utils"),
            (PackageManager::AptGet, "avahi_publish_service") => Some("avahi-daemon"),
            (PackageManager::AptGet, "docker") => Some("docker.io"),
            (PackageManager::AptGet, "gh") => Some("gh"),
            (PackageManager::AptGet, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::AptGet, "openssl") => Some("openssl"),
            (PackageManager::AptGet, "ssh") => Some("openssh-client"),
            (PackageManager::Brew, "gh") => Some("gh"),
            (PackageManager::Brew, "openssl") => Some("openssl@3"),
            (PackageManager::Dnf, "avahi_browse") => Some("avahi-tools"),
            (PackageManager::Dnf, "avahi_publish_service") => Some("avahi"),
            (PackageManager::Dnf, "docker") => Some("moby-engine"),
            (PackageManager::Dnf, "gh") => Some("gh"),
            (PackageManager::Dnf, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::Dnf, "openssl") => Some("openssl"),
            (PackageManager::Dnf, "ssh") => Some("openssh-clients"),
            (PackageManager::Pacman, "avahi_browse" | "avahi_publish_service") => Some("avahi"),
            (PackageManager::Pacman, "docker") => Some("docker"),
            (PackageManager::Pacman, "gh") => Some("github-cli"),
            (PackageManager::Pacman, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::Pacman, "openssl") => Some("openssl"),
            (PackageManager::Pacman, "ssh") => Some("openssh"),
            (PackageManager::Zypper, "avahi_browse") => Some("avahi-utils"),
            (PackageManager::Zypper, "avahi_publish_service") => Some("avahi"),
            (PackageManager::Zypper, "docker") => Some("docker"),
            (PackageManager::Zypper, "gh") => Some("gh"),
            (PackageManager::Zypper, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::Zypper, "openssl") => Some("openssl"),
            (PackageManager::Zypper, "ssh") => Some("openssh"),
            _ => None,
        }
    }

    // Returns the exact noninteractive arguments for one package transaction.
    fn installation_arguments(self, packages: &BTreeSet<String>) -> Vec<String> {
        let mut arguments = match self {
            PackageManager::AptGet | PackageManager::Dnf => {
                vec!["install".to_string(), "-y".to_string()]
            }
            PackageManager::Brew => vec!["install".to_string()],
            PackageManager::Pacman => vec![
                "-S".to_string(),
                "--noconfirm".to_string(),
                "--needed".to_string(),
            ],
            PackageManager::Zypper => {
                vec!["--non-interactive".to_string(), "install".to_string()]
            }
        };
        arguments.extend(packages.iter().cloned());
        arguments
    }
}

// Returns deterministic native package transactions for the observed dependency state.
fn package_transactions(
    document: &ProbeDocument,
    manager: PackageManager,
    packages: &BTreeSet<String>,
) -> Vec<Vec<String>> {
    if manager != PackageManager::Brew {
        return vec![manager.installation_arguments(packages)];
    }

    let mut installations = packages.clone();
    let upgrade_github_cli = installations.contains("gh")
        && document.dependencies.get("gh").is_some_and(|observation| {
            !observation.path.is_empty() && !github_cli_version_is_supported(&observation.version)
        });
    if upgrade_github_cli {
        installations.remove("gh");
    }

    let mut transactions = Vec::new();
    if !installations.is_empty() {
        transactions.push(manager.installation_arguments(&installations));
    }
    if upgrade_github_cli {
        transactions.push(vec!["upgrade".to_string(), "gh".to_string()]);
    }
    transactions
}

// Reads and parses one bounded installation-probe document.
fn read_probe_document(
    native: &mut impl NativeActions,
    path: &Path,
) -> Result<ProbeDocument, String> {
    let bytes = native.read_file(path, MAXIMUM_DOCUMENT_BYTES)?;
    let document =
        String::from_utf8(bytes).map_err(|_| "installation probe is not UTF-8".to_string())?;
    parsed_probe_document(JsonParser::new(&document).parse()?)
}

// Converts one parsed JSON root into the dependency-manager contract.
fn parsed_probe_document(value: JsonValue) -> Result<ProbeDocument, String> {
    let root = required_object(&value, "installation probe")?;
    let schema = required_object(required_member(root, "schema")?, "schema")?;
    if required_string(schema, "name")? != INSTALLATION_PROBE_SCHEMA_NAME
        || required_number(schema, "version")? != INSTALLATION_PROBE_SCHEMA_VERSION.to_string()
    {
        return Err("installation probe schema identity is unsupported".to_string());
    }
    let status = required_string(root, "status")?;
    if !matches!(
        status,
        "ready" | "missing_dependencies" | "service_manager_unavailable"
    ) {
        return Err(format!(
            "installation probe status cannot be managed: {}",
            status
        ));
    }
    let platform = required_object(required_member(root, "platform")?, "platform")?;
    let platform_identifier = required_string(platform, "identifier")?.to_string();
    let service_manager_value =
        required_object(required_member(root, "service_manager")?, "service manager")?;
    let persistence = required_object(
        required_member(service_manager_value, "persistence")?,
        "service persistence",
    )?;
    let service_manager = ServiceManagerObservation {
        provider: required_string(service_manager_value, "provider")?.to_string(),
        scope: required_string(service_manager_value, "scope")?.to_string(),
        persistence_mechanism: required_string(persistence, "mechanism")?.to_string(),
        user_domain_available: required_boolean(service_manager_value, "user_domain_available")?,
        persistence_available: required_boolean(persistence, "available")?,
    };
    let valid_service_manager_identity = if platform_identifier.starts_with("linux-") {
        service_manager.provider == "systemd"
            && service_manager.scope == "user"
            && service_manager.persistence_mechanism == "systemd-linger"
    } else if platform_identifier.starts_with("macos-") {
        service_manager.provider == "launchd"
            && service_manager.scope == "gui"
            && service_manager.persistence_mechanism == "launch-agent"
    } else {
        false
    };
    if !valid_service_manager_identity {
        return Err("service-manager identity does not match platform".to_string());
    }
    let hardware = required_object(required_member(root, "hardware")?, "hardware")?;
    let operating_system = required_object(
        required_member(hardware, "operating_system")?,
        "operating system",
    )?;
    let distribution = required_string(operating_system, "distribution")?.to_string();
    let dependency_values =
        required_object(required_member(root, "dependencies")?, "dependencies")?;
    let mut dependencies = BTreeMap::new();
    for (name, value) in dependency_values {
        if !is_valid_dependency_name(name) {
            return Err(format!("dependency name is invalid: {}", name));
        }
        let observation = required_object(value, name)?;
        required_string(observation, "version")?;
        dependencies.insert(
            name.clone(),
            DependencyObservation {
                version: required_string(observation, "version")?.to_string(),
                path: required_string(observation, "path")?.to_string(),
                installable: required_boolean(observation, "installable")?,
            },
        );
    }
    let errors = required_array(required_member(root, "errors")?, "errors")?;
    let mut required_missing_dependencies = BTreeSet::new();
    for value in errors {
        let error = value
            .as_string()
            .ok_or_else(|| "installation probe error is not a string".to_string())?;
        if let Some(name) = error.strip_prefix("missing dependency: ") {
            if !dependencies.contains_key(name) {
                return Err(format!("missing dependency is not observed: {}", name));
            }
            required_missing_dependencies.insert(name.to_string());
        } else if error
            == format!(
                "service manager user domain is unavailable: {}",
                service_manager.provider
            )
            && !service_manager.user_domain_available
        {
            continue;
        } else if error
            == format!(
                "service persistence is unavailable: {}",
                service_manager.persistence_mechanism
            )
            && !service_manager.persistence_available
        {
            continue;
        } else {
            return Err(format!(
                "installation probe error cannot be managed: {}",
                error
            ));
        }
    }
    Ok(ProbeDocument {
        platform: platform_identifier,
        distribution,
        service_manager,
        dependencies,
        required_missing_dependencies,
    })
}

// Rejects service installation when its user domain or persistence is unavailable.
fn verify_service_manager_readiness(document: &ProbeDocument) -> Result<(), String> {
    if !document.service_manager.user_domain_available {
        return Err(format!(
            "service manager user domain is unavailable: {}",
            document.service_manager.provider
        ));
    }
    if !document.service_manager.persistence_available {
        return Err(format!(
            "service persistence is unavailable: {}",
            document.service_manager.persistence_mechanism
        ));
    }
    Ok(())
}

// Returns one required member from a parsed JSON object.
fn required_member<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, String> {
    object
        .get(name)
        .ok_or_else(|| format!("installation probe is missing field: {}", name))
}

// Returns one parsed object or a stable type failure.
fn required_object<'a>(
    value: &'a JsonValue,
    name: &str,
) -> Result<&'a BTreeMap<String, JsonValue>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("installation probe field is not an object: {}", name))
}

// Returns one parsed array or a stable type failure.
fn required_array<'a>(value: &'a JsonValue, name: &str) -> Result<&'a [JsonValue], String> {
    value
        .as_array()
        .ok_or_else(|| format!("installation probe field is not an array: {}", name))
}

// Returns one required string member from a parsed JSON object.
fn required_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, String> {
    required_member(object, name)?
        .as_string()
        .ok_or_else(|| format!("installation probe field is not a string: {}", name))
}

// Returns one required boolean member from a parsed JSON object.
fn required_boolean(object: &BTreeMap<String, JsonValue>, name: &str) -> Result<bool, String> {
    required_member(object, name)?
        .as_boolean()
        .ok_or_else(|| format!("installation probe field is not a boolean: {}", name))
}

// Returns one required number member from a parsed JSON object.
fn required_number<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, String> {
    required_member(object, name)?
        .as_number()
        .ok_or_else(|| format!("installation probe field is not a number: {}", name))
}

// Returns whether one dependency name belongs to the closed machine vocabulary.
fn is_valid_dependency_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

// Parses the canonical first line emitted by `gh --version`.
fn github_cli_version(value: &str) -> Option<(u64, u64, u64)> {
    let first_line = value.lines().next()?;
    let version = first_line
        .strip_prefix("gh version ")?
        .split_whitespace()
        .next()?;
    let mut components = version.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

// Returns whether one GitHub CLI observation satisfies Core's minimum contract.
pub(crate) fn github_cli_version_is_supported(value: &str) -> bool {
    github_cli_version(value).is_some_and(|version| version >= GITHUB_CLI_MINIMUM_VERSION)
}

// Returns whether one observed dependency is currently usable.
fn dependency_is_available(name: &str, observation: &DependencyObservation) -> bool {
    if observation.path.is_empty() {
        return false;
    }
    name != "gh" || github_cli_version_is_supported(&observation.version)
}

// Selects the native package manager from the observed platform identity.
fn package_manager(document: &ProbeDocument) -> Result<PackageManager, String> {
    if document.platform.starts_with("macos-") {
        return Ok(PackageManager::Brew);
    }
    if !document.platform.starts_with("linux-") {
        return Err(format!(
            "dependency-manager platform is unsupported: {}",
            document.platform
        ));
    }
    match document.distribution.as_str() {
        "ubuntu" | "debian" | "linuxmint" | "pop" => Ok(PackageManager::AptGet),
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "amzn" => Ok(PackageManager::Dnf),
        "arch" | "manjaro" => Ok(PackageManager::Pacman),
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" => Ok(PackageManager::Zypper),
        value => Err(format!("Linux distribution is unsupported: {}", value)),
    }
}

// Rejects required missing dependencies that have no approved installation path.
fn verify_required_dependencies(document: &ProbeDocument) -> Result<(), String> {
    for name in &document.required_missing_dependencies {
        let observation = document
            .dependencies
            .get(name)
            .ok_or_else(|| format!("required dependency is not observed: {}", name))?;
        if dependency_is_available(name, observation) {
            return Err(format!(
                "required dependency observation is inconsistent: {}",
                name
            ));
        }
        if !observation.installable {
            return Err(format!("required dependency is not installable: {}", name));
        }
    }
    Ok(())
}

// Resolves the deduplicated package transaction for every missing installable dependency.
fn package_plan(
    document: &ProbeDocument,
    manager: PackageManager,
) -> Result<BTreeSet<String>, String> {
    let mut packages = BTreeSet::new();
    for (name, observation) in &document.dependencies {
        if dependency_is_available(name, observation) || !observation.installable {
            continue;
        }
        let package = manager.package_name(name).ok_or_else(|| {
            format!(
                "installable dependency has no {} package mapping: {}",
                manager.dependency_name(),
                name
            )
        })?;
        packages.insert(package.to_string());
    }
    Ok(packages)
}

// Returns every installable dependency absent from the observed command paths.
fn missing_installable_dependencies(document: &ProbeDocument) -> BTreeSet<String> {
    document
        .dependencies
        .iter()
        .filter(|(name, observation)| {
            !dependency_is_available(name, observation) && observation.installable
        })
        .map(|(name, _)| name.clone())
        .collect()
}

// Returns one observed executable path after enforcing the native boundary.
fn dependency_executable<'a>(
    native: &mut impl NativeActions,
    document: &'a ProbeDocument,
    name: &str,
) -> Result<&'a str, String> {
    let path = document
        .dependencies
        .get(name)
        .map(|value| value.path.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("dependency executable is unavailable: {}", name))?;
    native.validate_executable(Path::new(path))?;
    Ok(path)
}

// Returns whether the injected native identity command reports root.
fn effective_user_is_root(native: &mut impl NativeActions, command: &Path) -> Result<bool, String> {
    native.validate_executable(command)?;
    let output = native.run_command(command, &["-u".to_string()], &[])?;
    if !output.success {
        return Err("identity command failed".to_string());
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "identity command output is not UTF-8".to_string())?;
    match value.trim() {
        "0" => Ok(true),
        value if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => Ok(false),
        _ => Err("identity command returned an invalid user identifier".to_string()),
    }
}

// Returns the stable lowercase SHA-256 identity of one byte sequence.
fn sha256_hex(contents: &[u8]) -> String {
    Sha256::digest(contents)
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

// Returns the official architecture-qualified GitHub CLI apt source entry.
fn github_cli_source(
    document: &ProbeDocument,
    repository: &GitHubCliRepository<'_>,
) -> Result<String, String> {
    let architecture = match document.platform.as_str() {
        "linux-arm64" => "arm64",
        "linux-x86_64" => "amd64",
        value => return Err(format!("GitHub CLI apt platform is unsupported: {}", value)),
    };
    Ok(format!(
        "deb [arch={} signed-by={}] https://cli.github.com/packages stable main\n",
        architecture, repository.keyring_path
    ))
}

// Runs one command and converts its bounded failure into a stable diagnostic.
fn run_checked_command(
    native: &mut impl NativeActions,
    command: &Path,
    arguments: &[String],
    environment: &[(&str, &str)],
    failure: &str,
) -> Result<(), String> {
    let output = native.run_command(command, arguments, environment)?;
    if output.success {
        return Ok(());
    }
    Err(format!(
        "{}: {}",
        failure,
        command_failure_detail(&output.stdout, &output.stderr)
    ))
}

// Runs one exact privileged command directly as root or through injected sudo.
fn run_privileged_command(
    native: &mut impl NativeActions,
    sudo_path: Option<&Path>,
    command: &Path,
    arguments: &[String],
    environment: &[(&str, &str)],
    failure: &str,
) -> Result<(), String> {
    if let Some(sudo_path) = sudo_path {
        let mut sudo_arguments = vec!["--".to_string(), command.to_string_lossy().into_owned()];
        sudo_arguments.extend(arguments.iter().cloned());
        run_checked_command(native, sudo_path, &sudo_arguments, environment, failure)
    } else {
        run_checked_command(native, command, arguments, environment, failure)
    }
}

// Configures GitHub CLI's pinned official apt repository before package refresh.
fn configure_github_cli_apt_repository(
    native: &mut impl NativeActions,
    document: &ProbeDocument,
    probe_file: &Path,
    sudo_path: Option<&Path>,
    repository: &GitHubCliRepository<'_>,
) -> Result<(), String> {
    let temporary_root = probe_file
        .parent()
        .ok_or_else(|| "installation probe has no temporary root".to_string())?;
    let keyring_file = temporary_root.join("li_installer_github_cli_keyring.gpg");
    let source_file = temporary_root.join("li_installer_github_cli_source.list");
    native.write_new_file(&keyring_file, b"reserved")?;

    let result = (|| {
        let curl_path = PathBuf::from(dependency_executable(native, document, "curl")?);
        let curl_arguments = vec![
            "--fail".to_string(),
            "--silent".to_string(),
            "--show-error".to_string(),
            "--location".to_string(),
            "--proto".to_string(),
            "=https".to_string(),
            "--proto-redir".to_string(),
            "=https".to_string(),
            "--tlsv1.2".to_string(),
            "--output".to_string(),
            keyring_file.to_string_lossy().into_owned(),
            repository.keyring_url.to_string(),
        ];
        run_checked_command(
            native,
            &curl_path,
            &curl_arguments,
            &[],
            "GitHub CLI keyring download failed",
        )?;
        let keyring = native.read_file(&keyring_file, MAXIMUM_DOCUMENT_BYTES)?;
        let observed_hash = sha256_hex(&keyring);
        if observed_hash != repository.keyring_sha256 {
            return Err(format!(
                "GitHub CLI keyring SHA-256 is invalid: {}",
                observed_hash
            ));
        }

        let source = github_cli_source(document, repository)?;
        native.write_new_file(&source_file, source.as_bytes())?;
        let install_path = PathBuf::from(dependency_executable(native, document, "install")?);
        for (arguments, failure) in [
            (
                vec![
                    "-d".to_string(),
                    "-m".to_string(),
                    "0755".to_string(),
                    "/etc/apt/keyrings".to_string(),
                ],
                "GitHub CLI keyring directory installation failed",
            ),
            (
                vec![
                    "-m".to_string(),
                    "0644".to_string(),
                    keyring_file.to_string_lossy().into_owned(),
                    repository.keyring_path.to_string(),
                ],
                "GitHub CLI keyring installation failed",
            ),
            (
                vec![
                    "-d".to_string(),
                    "-m".to_string(),
                    "0755".to_string(),
                    repository.source_directory.to_string(),
                ],
                "GitHub CLI source directory installation failed",
            ),
            (
                vec![
                    "-m".to_string(),
                    "0644".to_string(),
                    source_file.to_string_lossy().into_owned(),
                    repository.source_path.to_string(),
                ],
                "GitHub CLI source installation failed",
            ),
        ] {
            run_privileged_command(native, sudo_path, &install_path, &arguments, &[], failure)?;
        }
        Ok(())
    })();

    let keyring_cleanup = native.remove_file_if_present(&keyring_file);
    let source_cleanup = native.remove_file_if_present(&source_file);
    result?;
    keyring_cleanup?;
    source_cleanup
}

// Runs one native package transaction without a shell or inherited output.
fn install_packages(
    native: &mut impl NativeActions,
    document: &ProbeDocument,
    manager: PackageManager,
    packages: &BTreeSet<String>,
    probe_file: &Path,
    id_command: &Path,
    github_repository: &GitHubCliRepository<'_>,
) -> Result<(), String> {
    let manager_path = PathBuf::from(dependency_executable(
        native,
        document,
        manager.dependency_name(),
    )?);
    let transactions = package_transactions(document, manager, packages);
    let requires_privilege =
        manager != PackageManager::Brew && !effective_user_is_root(native, id_command)?;
    let sudo_path = if requires_privilege {
        Some(PathBuf::from(dependency_executable(
            native, document, "sudo",
        )?))
    } else {
        None
    };
    if manager == PackageManager::AptGet && packages.contains("gh") {
        configure_github_cli_apt_repository(
            native,
            document,
            probe_file,
            sudo_path.as_deref(),
            github_repository,
        )?;
    }
    if manager == PackageManager::AptGet {
        run_privileged_command(
            native,
            sudo_path.as_deref(),
            &manager_path,
            &["update".to_string(), "-qq".to_string()],
            &[],
            "package metadata refresh failed",
        )?;
    }
    let environment = if manager == PackageManager::AptGet {
        vec![("DEBIAN_FRONTEND", "noninteractive")]
    } else {
        Vec::new()
    };
    for arguments in transactions {
        run_privileged_command(
            native,
            sudo_path.as_deref(),
            &manager_path,
            &arguments,
            &environment,
            "package manager failed",
        )?;
    }
    Ok(())
}

// Enforces the bounded native command-output contract.
fn validate_command_output_size(stdout: &[u8], stderr: &[u8]) -> Result<(), String> {
    if stdout.len() > MAXIMUM_COMMAND_OUTPUT_BYTES || stderr.len() > MAXIMUM_COMMAND_OUTPUT_BYTES {
        return Err("native command output exceeded its boundary".to_string());
    }
    Ok(())
}

// Returns one concise diagnostic line from a failed native command.
fn command_failure_detail(stdout: &[u8], stderr: &[u8]) -> String {
    let source = if stderr.is_empty() { stdout } else { stderr };
    String::from_utf8_lossy(source)
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .unwrap_or("unknown package-manager error")
        .chars()
        .take(512)
        .collect()
}

// Applies or verifies the complete dependency-manager lifecycle.
fn manage_dependencies(
    native: &mut impl NativeActions,
    arguments: &ManagerArguments,
    github_repository: &GitHubCliRepository<'_>,
) -> Result<&'static str, String> {
    let document = read_probe_document(native, &arguments.probe_file)?;
    verify_service_manager_readiness(&document)?;
    verify_required_dependencies(&document)?;
    if missing_installable_dependencies(&document).is_empty() {
        return Ok("unchanged");
    }
    let manager = package_manager(&document)?;
    let packages = package_plan(&document, manager)?;
    if arguments.mode == ManagerMode::Verify {
        return Err(format!(
            "installable dependencies remain unavailable: {}",
            packages.into_iter().collect::<Vec<_>>().join(",")
        ));
    }
    install_packages(
        native,
        &document,
        manager,
        &packages,
        &arguments.probe_file,
        &arguments.id_command,
        github_repository,
    )?;
    Ok("installed")
}

// Applies or verifies dependencies from one validated installation probe.
pub fn manage(
    mode: ManagerMode,
    probe_file: &Path,
    id_command: &Path,
) -> Result<DependencyManagerResult, String> {
    let arguments = ManagerArguments {
        mode,
        probe_file: probe_file.to_path_buf(),
        id_command: id_command.to_path_buf(),
    };
    match manage_dependencies(
        &mut SystemNativeActions,
        &arguments,
        &GitHubCliRepository::production(),
    )? {
        "installed" => Ok(DependencyManagerResult::Installed),
        "unchanged" => Ok(DependencyManagerResult::Unchanged),
        _ => Err("dependency-manager result is invalid".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Records one complete shell-free native command invocation.
    #[derive(Debug, Eq, PartialEq)]
    struct CommandInvocation {
        command: String,
        arguments: Vec<String>,
        environment: Vec<(String, String)>,
    }

    // Supplies deterministic files, commands, and a downloaded keyring to the real manager.
    struct MockNativeActions {
        commands: Vec<CommandInvocation>,
        download: Vec<u8>,
        executables: BTreeSet<PathBuf>,
        files: BTreeMap<PathBuf, Vec<u8>>,
        writes: Vec<(PathBuf, Vec<u8>)>,
    }

    impl MockNativeActions {
        // Creates one complete native boundary around an injected probe document.
        fn new(probe: &Path, document: String, download: &[u8]) -> Self {
            Self {
                commands: Vec::new(),
                download: download.to_vec(),
                executables: [
                    "/mock/apt-get",
                    "/mock/brew",
                    "/mock/curl",
                    "/mock/id",
                    "/mock/install",
                    "/mock/sudo",
                ]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
                files: BTreeMap::from([(probe.to_path_buf(), document.into_bytes())]),
                writes: Vec::new(),
            }
        }
    }

    impl NativeActions for MockNativeActions {
        // Reads one fixture file through the same byte boundary as production.
        fn read_file(&mut self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, String> {
            let contents = self
                .files
                .get(path)
                .filter(|value| !value.is_empty() && value.len() <= maximum_bytes)
                .ok_or_else(|| format!("mock file is unavailable: {}", path.display()))?;
            Ok(contents.clone())
        }

        // Creates one fixture file and rejects path reuse.
        fn write_new_file(&mut self, path: &Path, contents: &[u8]) -> Result<(), String> {
            if self.files.contains_key(path) {
                return Err(format!("mock file already exists: {}", path.display()));
            }
            self.files.insert(path.to_path_buf(), contents.to_vec());
            self.writes.push((path.to_path_buf(), contents.to_vec()));
            Ok(())
        }

        // Removes one exact fixture path without affecting neighboring state.
        fn remove_file_if_present(&mut self, path: &Path) -> Result<(), String> {
            self.files.remove(path);
            Ok(())
        }

        // Accepts only the closed executable inventory supplied by the fixture.
        fn validate_executable(&mut self, path: &Path) -> Result<(), String> {
            if self.executables.contains(path) {
                Ok(())
            } else {
                Err(format!(
                    "mock executable is unavailable: {}",
                    path.display()
                ))
            }
        }

        // Records exact argv/environment and emulates identity plus key download effects.
        fn run_command(
            &mut self,
            command: &Path,
            arguments: &[String],
            environment: &[(&str, &str)],
        ) -> Result<NativeCommandOutput, String> {
            self.commands.push(CommandInvocation {
                command: command.to_string_lossy().into_owned(),
                arguments: arguments.to_vec(),
                environment: environment
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
            });
            if command == Path::new("/mock/id") {
                return Ok(NativeCommandOutput {
                    success: true,
                    stdout: b"1000\n".to_vec(),
                    stderr: Vec::new(),
                });
            }
            if command == Path::new("/mock/curl") {
                let output_index = arguments
                    .iter()
                    .position(|value| value == "--output")
                    .ok_or_else(|| "mock curl output is unavailable".to_string())?;
                let output = arguments
                    .get(output_index + 1)
                    .ok_or_else(|| "mock curl output path is unavailable".to_string())?;
                self.files
                    .insert(PathBuf::from(output), self.download.clone());
            }
            Ok(NativeCommandOutput {
                success: true,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    // Returns one Linux probe whose only readiness judgment is GitHub CLI compatibility.
    fn github_probe_document(version: &str, is_ready: bool) -> String {
        let status = if is_ready {
            "ready"
        } else {
            "missing_dependencies"
        };
        let errors = if is_ready {
            "[]"
        } else {
            r#"["missing dependency: gh"]"#
        };
        format!(
            r#"{{
                "schema":{{"name":"letsinfer.installer.installation-probe","version":1}},
                "status":"{status}",
                "platform":{{"identifier":"linux-arm64"}},
                "service_manager":{{
                    "provider":"systemd",
                    "scope":"user",
                    "user_domain_available":true,
                    "persistence":{{"mechanism":"systemd-linger","available":true}}
                }},
                "dependencies":{{
                    "apt_get":{{"version":"apt fixture","path":"/mock/apt-get","installable":false}},
                    "curl":{{"version":"curl fixture","path":"/mock/curl","installable":false}},
                    "gh":{{"version":"{version}","path":"/mock/gh","installable":true}},
                    "install":{{"version":"install fixture","path":"/mock/install","installable":false}},
                    "sudo":{{"version":"sudo fixture","path":"/mock/sudo","installable":false}}
                }},
                "hardware":{{"operating_system":{{"distribution":"ubuntu"}}}},
                "errors":{errors}
            }}"#
        )
    }

    // Returns one macOS probe whose GitHub CLI and OpenSSL observations drive Brew actions.
    fn macos_github_probe_document(
        github_cli_path: &str,
        github_cli_version: &str,
        openssl_path: &str,
    ) -> String {
        let github_cli_is_available =
            !github_cli_path.is_empty() && github_cli_version_is_supported(github_cli_version);
        let openssl_is_available = !openssl_path.is_empty();
        let mut errors = Vec::new();
        if !github_cli_is_available {
            errors.push(r#""missing dependency: gh""#);
        }
        if !openssl_is_available {
            errors.push(r#""missing dependency: openssl""#);
        }
        let status = if errors.is_empty() {
            "ready"
        } else {
            "missing_dependencies"
        };
        format!(
            r#"{{
                "schema":{{"name":"letsinfer.installer.installation-probe","version":1}},
                "status":"{status}",
                "platform":{{"identifier":"macos-arm64"}},
                "service_manager":{{
                    "provider":"launchd",
                    "scope":"gui",
                    "user_domain_available":true,
                    "persistence":{{"mechanism":"launch-agent","available":true}}
                }},
                "dependencies":{{
                    "brew":{{"version":"brew fixture","path":"/mock/brew","installable":false}},
                    "gh":{{"version":"{github_cli_version}","path":"{github_cli_path}","installable":true}},
                    "openssl":{{"version":"openssl fixture","path":"{openssl_path}","installable":true}}
                }},
                "hardware":{{"operating_system":{{"distribution":"macos"}}}},
                "errors":[{}]
            }}"#,
            errors.join(",")
        )
    }

    // Returns one test repository whose trust hash binds the supplied keyring bytes.
    fn github_repository_for(hash: &str) -> GitHubCliRepository<'_> {
        GitHubCliRepository {
            keyring_url: GITHUB_CLI_KEYRING_URL,
            keyring_sha256: hash,
            keyring_path: GITHUB_CLI_KEYRING_PATH,
            source_directory: GITHUB_CLI_SOURCE_DIRECTORY,
            source_path: GITHUB_CLI_SOURCE_PATH,
        }
    }

    // Returns one complete probe fixture with missing installable dependencies.
    fn probe_fixture() -> JsonValue {
        JsonParser::new(
            r#"{
                "schema":{"name":"letsinfer.installer.installation-probe","version":1},
                "status":"missing_dependencies",
                "platform":{"identifier":"linux-arm64"},
                "service_manager":{
                    "provider":"systemd",
                    "scope":"user",
                    "user_domain_available":true,
                    "persistence":{"mechanism":"systemd-linger","available":true}
                },
                "dependencies":{
                    "apt_get":{"version":"apt fixture","path":"/mock/apt-get","installable":false},
                    "avahi_browse":{"version":"","path":"","installable":true},
                    "avahi_publish_service":{"version":"","path":"","installable":true},
                    "docker":{"version":"","path":"","installable":true},
                    "gh":{"version":"gh version 2.97.0 (fixture)","path":"/mock/gh","installable":true},
                    "sudo":{"version":"","path":"/mock/sudo","installable":false}
                },
                "hardware":{"operating_system":{"distribution":"ubuntu"}},
                "errors":["missing dependency: docker"]
            }"#,
        )
        .parse()
        .expect("fixture JSON should parse")
    }

    // Accepts the exact installation-probe fields consumed by the manager.
    #[test]
    fn parses_probe_contract() {
        let document = parsed_probe_document(probe_fixture()).expect("probe should parse");
        assert_eq!(document.platform, "linux-arm64");
        assert!(document.dependencies["docker"].installable);
        assert!(document.required_missing_dependencies.contains("docker"));
    }

    // Deduplicates package identities shared by multiple dependencies.
    #[test]
    fn deduplicates_native_packages() {
        let document = parsed_probe_document(probe_fixture()).expect("probe should parse");
        let packages =
            package_plan(&document, PackageManager::AptGet).expect("plan should resolve");
        assert_eq!(
            packages.into_iter().collect::<Vec<_>>(),
            vec!["avahi-daemon", "avahi-utils", "docker.io"]
        );
    }

    // Rejects required missing dependencies without an approved installation path.
    #[test]
    fn rejects_required_noninstallable_dependency() {
        let mut document = parsed_probe_document(probe_fixture()).expect("probe should parse");
        document.dependencies.get_mut("docker").unwrap().installable = false;
        assert!(verify_required_dependencies(&document)
            .expect_err("dependency should be rejected")
            .contains("not installable"));
    }

    // Rejects malformed JSON before any installation decision is made.
    #[test]
    fn rejects_malformed_json() {
        assert!(JsonParser::new("{\"schema\":").parse().is_err());
    }

    // Rejects package mutation before persistent user services are available.
    #[test]
    fn rejects_unavailable_service_persistence() {
        let mut document = parsed_probe_document(probe_fixture()).expect("probe should parse");
        document.service_manager.persistence_available = false;
        assert!(verify_service_manager_readiness(&document)
            .expect_err("service persistence should be rejected")
            .contains("systemd-linger"));
    }

    // Classifies old and malformed GitHub CLI output as missing at the version boundary.
    #[test]
    fn github_cli_version_contract_is_closed() {
        for (version, is_supported) in [
            ("gh version 2.45.0 (fixture)", false),
            ("gh version 2.96.99 (fixture)", false),
            ("gh version 2.97.0 (fixture)", true),
            ("gh version 2.100.1 (fixture)", true),
            ("gh version 2.97 (fixture)", false),
            ("gh version v2.97.0 (fixture)", false),
            ("github cli 2.97.0", false),
            ("", false),
        ] {
            assert_eq!(
                github_cli_version_is_supported(version),
                is_supported,
                "unexpected classification for {version:?}"
            );
        }
    }

    // Classifies absent, old, malformed, and compatible GitHub CLI observations exactly.
    #[test]
    fn github_cli_observation_controls_readiness() {
        for (path, version, is_available) in [
            ("", "", false),
            ("/mock/gh", "gh version 2.45.0 (fixture)", false),
            ("/mock/gh", "malformed", false),
            ("/mock/gh", "gh version 2.97.0 (fixture)", true),
        ] {
            assert_eq!(
                dependency_is_available(
                    "gh",
                    &DependencyObservation {
                        version: version.to_string(),
                        path: path.to_string(),
                        installable: true,
                    }
                ),
                is_available,
                "unexpected GitHub CLI observation: path={path:?}, version={version:?}"
            );
        }

        let value = JsonParser::new(&github_probe_document("gh version 2.45.0 (fixture)", false))
            .parse()
            .expect("old GitHub CLI probe should parse");
        let document = parsed_probe_document(value).expect("old GitHub CLI probe should validate");
        assert_eq!(
            missing_installable_dependencies(&document),
            BTreeSet::from(["gh".to_string()])
        );
        assert_eq!(
            package_plan(&document, PackageManager::AptGet)
                .expect("GitHub CLI upgrade should resolve"),
            BTreeSet::from(["gh".to_string()])
        );
    }

    // Configures the pinned official apt repository before refreshing and upgrading GitHub CLI.
    #[test]
    fn github_cli_apt_mutation_has_exact_order_and_arguments() {
        let probe = PathBuf::from("/tmp/li_installer_test/probe.json");
        let keyring = b"trusted GitHub CLI keyring fixture";
        let mut native = MockNativeActions::new(
            &probe,
            github_probe_document("gh version 2.45.0 (fixture)", false),
            keyring,
        );
        let arguments = ManagerArguments {
            mode: ManagerMode::Apply,
            probe_file: probe.clone(),
            id_command: PathBuf::from("/mock/id"),
        };
        let keyring_hash = sha256_hex(keyring);

        assert_eq!(
            manage_dependencies(
                &mut native,
                &arguments,
                &github_repository_for(&keyring_hash),
            ),
            Ok("installed")
        );

        let temporary_keyring = "/tmp/li_installer_test/li_installer_github_cli_keyring.gpg";
        let temporary_source = "/tmp/li_installer_test/li_installer_github_cli_source.list";
        assert_eq!(
            native.commands,
            vec![
                CommandInvocation {
                    command: "/mock/id".to_string(),
                    arguments: vec!["-u".to_string()],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/curl".to_string(),
                    arguments: vec![
                        "--fail".to_string(),
                        "--silent".to_string(),
                        "--show-error".to_string(),
                        "--location".to_string(),
                        "--proto".to_string(),
                        "=https".to_string(),
                        "--proto-redir".to_string(),
                        "=https".to_string(),
                        "--tlsv1.2".to_string(),
                        "--output".to_string(),
                        temporary_keyring.to_string(),
                        GITHUB_CLI_KEYRING_URL.to_string(),
                    ],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/sudo".to_string(),
                    arguments: vec![
                        "--".to_string(),
                        "/mock/install".to_string(),
                        "-d".to_string(),
                        "-m".to_string(),
                        "0755".to_string(),
                        "/etc/apt/keyrings".to_string(),
                    ],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/sudo".to_string(),
                    arguments: vec![
                        "--".to_string(),
                        "/mock/install".to_string(),
                        "-m".to_string(),
                        "0644".to_string(),
                        temporary_keyring.to_string(),
                        GITHUB_CLI_KEYRING_PATH.to_string(),
                    ],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/sudo".to_string(),
                    arguments: vec![
                        "--".to_string(),
                        "/mock/install".to_string(),
                        "-d".to_string(),
                        "-m".to_string(),
                        "0755".to_string(),
                        GITHUB_CLI_SOURCE_DIRECTORY.to_string(),
                    ],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/sudo".to_string(),
                    arguments: vec![
                        "--".to_string(),
                        "/mock/install".to_string(),
                        "-m".to_string(),
                        "0644".to_string(),
                        temporary_source.to_string(),
                        GITHUB_CLI_SOURCE_PATH.to_string(),
                    ],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/sudo".to_string(),
                    arguments: vec![
                        "--".to_string(),
                        "/mock/apt-get".to_string(),
                        "update".to_string(),
                        "-qq".to_string(),
                    ],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/sudo".to_string(),
                    arguments: vec![
                        "--".to_string(),
                        "/mock/apt-get".to_string(),
                        "install".to_string(),
                        "-y".to_string(),
                        "gh".to_string(),
                    ],
                    environment: vec![(
                        "DEBIAN_FRONTEND".to_string(),
                        "noninteractive".to_string(),
                    )],
                },
            ]
        );
        assert!(native.writes.iter().any(|(path, contents)| {
            path == Path::new(temporary_source)
                && contents
                    == b"deb [arch=arm64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n"
        }));
    }

    // Rejects an untrusted keyring before the first privileged host mutation.
    #[test]
    fn github_cli_key_hash_fails_before_sudo_mutation() {
        let probe = PathBuf::from("/tmp/li_installer_test/probe.json");
        let mut native = MockNativeActions::new(
            &probe,
            github_probe_document("malformed", false),
            b"untrusted keyring",
        );
        let arguments = ManagerArguments {
            mode: ManagerMode::Apply,
            probe_file: probe,
            id_command: PathBuf::from("/mock/id"),
        };
        let error =
            manage_dependencies(&mut native, &arguments, &GitHubCliRepository::production())
                .expect_err("untrusted keyring should fail");
        assert!(error.contains("keyring SHA-256 is invalid"));
        assert_eq!(
            native
                .commands
                .iter()
                .filter(|invocation| invocation.command == "/mock/sudo")
                .count(),
            0
        );
        assert_eq!(GITHUB_CLI_KEYRING_SHA256.len(), 64);
    }

    // Requires a fresh compatible probe after package installation before verification passes.
    #[test]
    fn github_cli_installation_requires_compatible_reprobe() {
        let probe = PathBuf::from("/tmp/li_installer_test/probe.json");
        let keyring = b"trusted GitHub CLI keyring fixture";
        let keyring_hash = sha256_hex(keyring);
        let repository = github_repository_for(&keyring_hash);
        let mut native = MockNativeActions::new(
            &probe,
            github_probe_document("gh version 2.45.0 (fixture)", false),
            keyring,
        );
        let apply = ManagerArguments {
            mode: ManagerMode::Apply,
            probe_file: probe.clone(),
            id_command: PathBuf::from("/mock/id"),
        };
        assert_eq!(
            manage_dependencies(&mut native, &apply, &repository),
            Ok("installed")
        );

        native.files.insert(
            probe.clone(),
            github_probe_document("gh version 2.96.0 (fixture)", false).into_bytes(),
        );
        let verify = ManagerArguments {
            mode: ManagerMode::Verify,
            probe_file: probe.clone(),
            id_command: PathBuf::from("/mock/id"),
        };
        assert!(manage_dependencies(&mut native, &verify, &repository)
            .expect_err("old re-probe should fail")
            .contains("installable dependencies remain unavailable: gh"));

        native.files.insert(
            probe,
            github_probe_document("gh version 2.97.0 (fixture)", true).into_bytes(),
        );
        assert_eq!(
            manage_dependencies(&mut native, &verify, &repository),
            Ok("unchanged")
        );
    }

    // Upgrades an installed old GitHub CLI explicitly after other Brew installations.
    #[test]
    fn macos_old_github_cli_has_explicit_upgrade_order() {
        let probe = PathBuf::from("/tmp/li_installer_test/probe.json");
        let mut native = MockNativeActions::new(
            &probe,
            macos_github_probe_document("/mock/gh", "gh version 2.68.1 (fixture)", ""),
            &[],
        );
        let arguments = ManagerArguments {
            mode: ManagerMode::Apply,
            probe_file: probe,
            id_command: PathBuf::from("/mock/id"),
        };
        let repository = GitHubCliRepository::production();

        assert_eq!(
            manage_dependencies(&mut native, &arguments, &repository),
            Ok("installed")
        );
        assert_eq!(
            native.commands,
            vec![
                CommandInvocation {
                    command: "/mock/brew".to_string(),
                    arguments: vec!["install".to_string(), "openssl@3".to_string()],
                    environment: Vec::new(),
                },
                CommandInvocation {
                    command: "/mock/brew".to_string(),
                    arguments: vec!["upgrade".to_string(), "gh".to_string()],
                    environment: Vec::new(),
                },
            ]
        );
    }

    // Installs GitHub CLI when it is absent instead of asking Brew to upgrade it.
    #[test]
    fn macos_absent_github_cli_uses_install() {
        let probe = PathBuf::from("/tmp/li_installer_test/probe.json");
        let mut native = MockNativeActions::new(
            &probe,
            macos_github_probe_document("", "", "/mock/openssl"),
            &[],
        );
        let arguments = ManagerArguments {
            mode: ManagerMode::Apply,
            probe_file: probe,
            id_command: PathBuf::from("/mock/id"),
        };
        let repository = GitHubCliRepository::production();

        assert_eq!(
            manage_dependencies(&mut native, &arguments, &repository),
            Ok("installed")
        );
        assert_eq!(
            native.commands,
            vec![CommandInvocation {
                command: "/mock/brew".to_string(),
                arguments: vec!["install".to_string(), "gh".to_string()],
                environment: Vec::new(),
            }]
        );
    }

    // Requires the macOS re-probe to prove the explicit upgrade reached the minimum version.
    #[test]
    fn macos_github_cli_upgrade_requires_compatible_reprobe() {
        let probe = PathBuf::from("/tmp/li_installer_test/probe.json");
        let mut native = MockNativeActions::new(
            &probe,
            macos_github_probe_document("/mock/gh", "gh version 2.68.1 (fixture)", "/mock/openssl"),
            &[],
        );
        let apply = ManagerArguments {
            mode: ManagerMode::Apply,
            probe_file: probe.clone(),
            id_command: PathBuf::from("/mock/id"),
        };
        let repository = GitHubCliRepository::production();
        assert_eq!(
            manage_dependencies(&mut native, &apply, &repository),
            Ok("installed")
        );

        let verify = ManagerArguments {
            mode: ManagerMode::Verify,
            probe_file: probe.clone(),
            id_command: PathBuf::from("/mock/id"),
        };
        native.files.insert(
            probe.clone(),
            macos_github_probe_document("/mock/gh", "gh version 2.96.0 (fixture)", "/mock/openssl")
                .into_bytes(),
        );
        assert!(manage_dependencies(&mut native, &verify, &repository)
            .expect_err("old macOS re-probe should fail")
            .contains("installable dependencies remain unavailable: gh"));

        native.files.insert(
            probe,
            macos_github_probe_document("/mock/gh", "gh version 2.97.0 (fixture)", "/mock/openssl")
                .into_bytes(),
        );
        assert_eq!(
            manage_dependencies(&mut native, &verify, &repository),
            Ok("unchanged")
        );
    }
}
