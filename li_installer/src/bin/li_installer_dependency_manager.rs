// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use li_installer::{
    DEPENDENCIES_INSTALLED_EVENT, DEPENDENCIES_READY_EVENT, DEPENDENCIES_VERIFIED_EVENT,
    INSTALLATION_PROBE_SCHEMA_NAME, INSTALLATION_PROBE_SCHEMA_VERSION,
};

const MAXIMUM_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_JSON_DEPTH: usize = 64;

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
enum ManagerMode {
    Apply,
    Verify,
}

// Stores every native construct supplied by the composition root.
struct ManagerArguments {
    mode: ManagerMode,
    probe_file: String,
    id_command: String,
}

impl ManagerArguments {
    // Parses the complete manager contract and rejects unknown arguments.
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut index = 0;
        while index < arguments.len() {
            let raw_name = &arguments[index];
            let name = raw_name
                .strip_prefix("--")
                .ok_or_else(|| format!("argument name is invalid: {}", raw_name))?;
            if !matches!(name, "id-command" | "mode" | "probe-file") {
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
        let mode = match required_argument(&values, "mode")? {
            "apply" => ManagerMode::Apply,
            "verify" => ManagerMode::Verify,
            _ => return Err("dependency-manager mode is invalid".to_string()),
        };
        Ok(Self {
            mode,
            probe_file: required_argument(&values, "probe-file")?.to_string(),
            id_command: required_argument(&values, "id-command")?.to_string(),
        })
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
            (PackageManager::AptGet, "avahi_browse" | "avahi_publish_service") => {
                Some("avahi-utils")
            }
            (PackageManager::AptGet, "cc") => Some("build-essential"),
            (PackageManager::AptGet, "cmake" | "ctest") => Some("cmake"),
            (PackageManager::AptGet, "docker") => Some("docker.io"),
            (PackageManager::AptGet, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::AptGet, "openssl") => Some("openssl"),
            (PackageManager::AptGet, "python") => Some("python3"),
            (PackageManager::AptGet, "ssh") => Some("openssh-client"),
            (PackageManager::Brew, "openssl") => Some("openssl@3"),
            (PackageManager::Brew, "python") => Some("python"),
            (PackageManager::Dnf, "avahi_browse" | "avahi_publish_service") => Some("avahi-tools"),
            (PackageManager::Dnf, "cc") => Some("gcc"),
            (PackageManager::Dnf, "cmake" | "ctest") => Some("cmake"),
            (PackageManager::Dnf, "docker") => Some("docker"),
            (PackageManager::Dnf, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::Dnf, "openssl") => Some("openssl"),
            (PackageManager::Dnf, "python") => Some("python3"),
            (PackageManager::Dnf, "ssh") => Some("openssh-clients"),
            (PackageManager::Pacman, "avahi_browse" | "avahi_publish_service") => Some("avahi"),
            (PackageManager::Pacman, "cc") => Some("base-devel"),
            (PackageManager::Pacman, "cmake" | "ctest") => Some("cmake"),
            (PackageManager::Pacman, "docker") => Some("docker"),
            (PackageManager::Pacman, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::Pacman, "openssl") => Some("openssl"),
            (PackageManager::Pacman, "python") => Some("python"),
            (PackageManager::Pacman, "ssh") => Some("openssh"),
            (PackageManager::Zypper, "avahi_browse" | "avahi_publish_service") => {
                Some("avahi-utils")
            }
            (PackageManager::Zypper, "cc") => Some("gcc"),
            (PackageManager::Zypper, "cmake" | "ctest") => Some("cmake"),
            (PackageManager::Zypper, "docker") => Some("docker"),
            (PackageManager::Zypper, "nvidia_ctk") => Some("nvidia-container-toolkit"),
            (PackageManager::Zypper, "openssl") => Some("openssl"),
            (PackageManager::Zypper, "python") => Some("python3"),
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

// Returns one required parsed argument without fabricating a default.
fn required_argument<'a>(
    values: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, String> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("required argument is missing: --{}", name))
}

// Reads and parses one bounded installation-probe document.
fn read_probe_document(path: &str) -> Result<ProbeDocument, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect installation probe: {}", error))?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() as usize > MAXIMUM_DOCUMENT_BYTES
    {
        return Err("installation probe file is not a bounded regular file".to_string());
    }
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read installation probe: {}", error))?;
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
        if !observation.path.is_empty() {
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
        if !observation.path.is_empty() || !observation.installable {
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
        .filter(|(_, observation)| observation.path.is_empty() && observation.installable)
        .map(|(name, _)| name.clone())
        .collect()
}

// Returns one observed executable path after enforcing the native boundary.
fn dependency_executable<'a>(document: &'a ProbeDocument, name: &str) -> Result<&'a str, String> {
    let path = document
        .dependencies
        .get(name)
        .map(|value| value.path.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("dependency executable is unavailable: {}", name))?;
    executable_path(path)
}

// Returns one executable path only when it is absolute and runnable.
fn executable_path(path: &str) -> Result<&str, String> {
    if !Path::new(path).is_absolute() {
        return Err(format!("command path is not absolute: {}", path));
    }
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect command path {}: {}", path, error))?;
    if !metadata.is_file() {
        return Err(format!("command path is not a regular file: {}", path));
    }
    Ok(path)
}

// Returns whether the injected native identity command reports root.
fn effective_user_is_root(command: &str) -> Result<bool, String> {
    let command = executable_path(command)?;
    let output = Command::new(command)
        .arg("-u")
        .output()
        .map_err(|error| format!("identity command could not run: {}", error))?;
    validate_command_output_size(&output.stdout, &output.stderr)?;
    if !output.status.success() {
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

// Runs one native package transaction without a shell or inherited output.
fn install_packages(
    document: &ProbeDocument,
    manager: PackageManager,
    packages: &BTreeSet<String>,
    id_command: &str,
) -> Result<(), String> {
    let manager_path = dependency_executable(document, manager.dependency_name())?;
    let arguments = manager.installation_arguments(packages);
    let requires_privilege =
        manager != PackageManager::Brew && !effective_user_is_root(id_command)?;
    let mut command = if requires_privilege {
        let sudo_path = dependency_executable(document, "sudo")?;
        let mut command = Command::new(sudo_path);
        command.arg(manager_path);
        command
    } else {
        Command::new(manager_path)
    };
    command.args(&arguments);
    if manager == PackageManager::AptGet {
        command.env("DEBIAN_FRONTEND", "noninteractive");
    }
    let output = command
        .output()
        .map_err(|error| format!("package manager could not run: {}", error))?;
    validate_command_output_size(&output.stdout, &output.stderr)?;
    if !output.status.success() {
        return Err(format!(
            "package manager failed: {}",
            command_failure_detail(&output.stdout, &output.stderr)
        ));
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
fn manage_dependencies(arguments: &ManagerArguments) -> Result<&'static str, String> {
    let document = read_probe_document(&arguments.probe_file)?;
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
    install_packages(&document, manager, &packages, &arguments.id_command)?;
    Ok("installed")
}

// Returns the semantic event associated with one completed manager lifecycle.
fn manager_event(mode: ManagerMode, result: &str) -> Result<&'static str, String> {
    match (mode, result) {
        (ManagerMode::Apply, "installed") => Ok(DEPENDENCIES_INSTALLED_EVENT),
        (ManagerMode::Apply, "unchanged") => Ok(DEPENDENCIES_READY_EVENT),
        (ManagerMode::Verify, "unchanged") => Ok(DEPENDENCIES_VERIFIED_EVENT),
        _ => Err("dependency-manager result has no event".to_string()),
    }
}

// Parses arguments, manages dependencies, and emits one stable result.
fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match ManagerArguments::parse(&arguments).and_then(|values| {
        let result = manage_dependencies(&values)?;
        Ok((result, manager_event(values.mode, result)?))
    }) {
        Ok((result, event)) => {
            eprintln!("{}", event);
            println!("{}", result);
        }
        Err(error) => {
            eprintln!("dependency manager: {}", error);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    "cc":{"version":"","path":"","installable":true},
                    "cmake":{"version":"","path":"","installable":true},
                    "ctest":{"version":"","path":"","installable":true},
                    "sudo":{"version":"","path":"/mock/sudo","installable":false}
                },
                "hardware":{"operating_system":{"distribution":"ubuntu"}},
                "errors":["missing dependency: cc"]
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
        assert!(document.dependencies["cc"].installable);
        assert!(document.required_missing_dependencies.contains("cc"));
    }

    // Deduplicates package identities shared by multiple dependencies.
    #[test]
    fn deduplicates_native_packages() {
        let document = parsed_probe_document(probe_fixture()).expect("probe should parse");
        let packages =
            package_plan(&document, PackageManager::AptGet).expect("plan should resolve");
        assert_eq!(
            packages.into_iter().collect::<Vec<_>>(),
            vec!["avahi-utils", "build-essential", "cmake"]
        );
    }

    // Rejects required missing dependencies without an approved installation path.
    #[test]
    fn rejects_required_noninstallable_dependency() {
        let mut document = parsed_probe_document(probe_fixture()).expect("probe should parse");
        document.dependencies.get_mut("cc").unwrap().installable = false;
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

    // Maps completed manager lifecycles to closed semantic display events.
    #[test]
    fn reports_semantic_events() {
        assert_eq!(
            manager_event(ManagerMode::Apply, "installed").unwrap(),
            DEPENDENCIES_INSTALLED_EVENT
        );
        assert_eq!(
            manager_event(ManagerMode::Verify, "unchanged").unwrap(),
            DEPENDENCIES_VERIFIED_EVENT
        );
    }
}
