// SPDX-License-Identifier: AGPL-3.0-only

use crate::InterfaceError;

const MAX_DISPLAY_NAME_BYTES: usize = 128;
const MAX_EXTERNAL_VALUE_BYTES: usize = 255;
const MAX_FAILURE_MESSAGE_BYTES: usize = 1024;
const MAX_TECHNICAL_NAME_BYTES: usize = 64;

// Identifies one supported host operating system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatingSystem {
    Linux,
    Macos,
}

// Identifies one supported host CPU architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuArchitecture {
    Arm64,
    X86_64,
}

// Stores one lowercase technical name used by an internal contract.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TechnicalName(String);

impl TechnicalName {
    // Parses one bounded lowercase name with stable separator rules.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_technical_name(value) {
            return Err(InterfaceError::new(
                "technical name",
                "name must use 1 to 64 lowercase letters, numbers, dots, underscores, or hyphens",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical technical name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one user-facing name without control characters.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayName(String);

impl DisplayName {
    // Parses one bounded canonical display name.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_bounded_text(value, MAX_DISPLAY_NAME_BYTES, true) {
            return Err(InterfaceError::new(
                "display name",
                "name must be canonical, non-empty, and at most 128 bytes",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical display name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one logical model name exposed by Core.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalModelName(TechnicalName);

impl LogicalModelName {
    // Parses one canonical logical model name.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        TechnicalName::parse(value).map(Self)
    }

    // Returns the canonical logical model name.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Stores one exact four-part runtime candidate identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeCandidateId(String);

impl RuntimeCandidateId {
    // Parses `<engine>--<owner>--<model>--<target>` in canonical lowercase form.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        let parts: Vec<&str> = value.split("--").collect();
        if parts.len() != 4 || parts.iter().any(|part| !is_candidate_component(part)) {
            return Err(InterfaceError::new(
                "runtime candidate identity",
                "identity must contain four canonical lowercase components",
            ));
        }
        if value.len() > 512 {
            return Err(InterfaceError::new(
                "runtime candidate identity",
                "identity exceeds 512 bytes",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the exact runtime candidate identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one exact runtime release version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeVersion(String);

impl RuntimeVersion {
    // Parses one bounded semantic-version-shaped release identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        let (core, suffix) = value
            .split_once('-')
            .map_or((value, None), |(core, suffix)| (core, Some(suffix)));
        let numeric: Vec<&str> = core.split('.').collect();
        let valid_numeric = numeric.len() == 3
            && numeric
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
        let valid_suffix = suffix.is_none_or(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        });
        if value.len() > 128 || !valid_numeric || !valid_suffix {
            return Err(InterfaceError::new(
                "runtime version",
                "version must contain three numeric components and an optional release suffix",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the exact runtime version.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one canonical runtime target identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetId(TechnicalName);

impl TargetId {
    // Parses one canonical runtime target identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        TechnicalName::parse(value).map(Self)
    }

    // Returns the canonical runtime target identity.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Stores one immutable OCI or local runtime source identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeSource(String);

impl RuntimeSource {
    // Parses one digest-pinned runtime source without resolving it.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        let digest = if let Some(value) = value.strip_prefix("letsinfer-object:sha256:") {
            Some(value)
        } else {
            value
                .rsplit_once("@sha256:")
                .filter(|(location, _)| {
                    !location.is_empty()
                        && !location.chars().any(char::is_whitespace)
                        && !location.chars().any(char::is_control)
                })
                .map(|(_, digest)| digest)
        };
        if value.len() > 1024 || digest.is_none_or(|digest| !is_lower_hex(digest, 64)) {
            return Err(InterfaceError::new(
                "runtime source",
                "source must be an immutable OCI or local SHA-256 identity",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the immutable runtime source identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one exact SHA-256 digest without an algorithm prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    // Parses one canonical lowercase SHA-256 digest.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_lower_hex(value, 64) {
            return Err(InterfaceError::new(
                "SHA-256 digest",
                "digest must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the canonical digest without an algorithm prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one opaque runtime task identity in canonical `task-N` form.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskId(String);

impl TaskId {
    // Parses one opaque task identity without assigning engine semantics.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        let index = value.strip_prefix("task-");
        let is_valid = index.is_some_and(|index| {
            index == "0"
                || (index.starts_with(|character: char| ('1'..='9').contains(&character))
                    && index.bytes().all(|byte| byte.is_ascii_digit()))
        });
        if !is_valid {
            return Err(InterfaceError::new(
                "task identity",
                "identity must use canonical task-N form",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the opaque task identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one accelerator identity reported by its platform provider.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(String);

impl DeviceId {
    // Parses one bounded opaque device identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_bounded_text(value, MAX_EXTERNAL_VALUE_BYTES, false) {
            return Err(InterfaceError::new(
                "device identity",
                "identity must be canonical, non-empty, and at most 255 bytes",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the opaque device identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one hostname or numeric network address without resolving it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeAddress(String);

impl NodeAddress {
    // Parses one bounded address without performing network I/O.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_bounded_text(value, MAX_EXTERNAL_VALUE_BYTES, false)
            || value.chars().any(char::is_whitespace)
        {
            return Err(InterfaceError::new(
                "node address",
                "address must be canonical, contain no whitespace, and be at most 255 bytes",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the unresolved node address.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one native network-interface name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkInterfaceName(String);

impl NetworkInterfaceName {
    // Parses one bounded Linux or macOS interface name.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        let valid_rest = bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'));
        if value.len() > 32 || !valid_first || !valid_rest {
            return Err(InterfaceError::new(
                "network interface",
                "name must use 1 to 32 native interface characters",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the native network-interface name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one host boot identity used to scope mutable observations.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BootId(String);

impl BootId {
    // Parses one bounded opaque host boot identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_bounded_text(value, 128, false) || value.chars().any(char::is_whitespace) {
            return Err(InterfaceError::new(
                "boot identity",
                "identity must be canonical, contain no whitespace, and be at most 128 bytes",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the opaque host boot identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one model artifact name within an installation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactName(TechnicalName);

impl ArtifactName {
    // Parses one canonical artifact name.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        TechnicalName::parse(value).map(Self)
    }

    // Returns the canonical artifact name.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// Stores one exact Hugging Face repository identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactUri(String);

impl ArtifactUri {
    // Parses one canonical `hf://owner/repository` identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        let parts: Vec<&str> = value
            .strip_prefix("hf://")
            .map(|value| value.split('/').collect())
            .unwrap_or_default();
        let valid_parts = parts.len() == 2
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part.len() <= 128
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if value.len() > 512 || !valid_parts {
            return Err(InterfaceError::new(
                "artifact URI",
                "URI must use canonical hf://owner/repository form",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the exact artifact repository identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one exact Hugging Face commit revision.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactRevision(String);

impl ArtifactRevision {
    // Parses one full lowercase Git commit identity.
    pub fn parse(value: &str) -> Result<Self, InterfaceError> {
        if !is_lower_hex(value, 40) {
            return Err(InterfaceError::new(
                "artifact revision",
                "revision must be exactly 40 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value.to_string()))
    }

    // Returns the exact artifact revision.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Stores one positive byte count.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteCount(u64);

impl ByteCount {
    // Creates one non-zero byte count.
    pub fn new(value: u64) -> Result<Self, InterfaceError> {
        if value == 0 {
            return Err(InterfaceError::new(
                "byte count",
                "value must be greater than zero",
            ));
        }
        Ok(Self(value))
    }

    // Returns the exact byte count.
    pub const fn value(self) -> u64 {
        self.0
    }
}

// Stores one non-negative Unix timestamp in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixMilliseconds(u64);

impl UnixMilliseconds {
    // Creates one exact Unix timestamp supplied by an owning clock.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    // Returns the exact Unix timestamp in milliseconds.
    pub const fn value(self) -> u64 {
        self.0
    }
}

// Stores one coherent creation and update timestamp pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityTimestamps {
    created_at: UnixMilliseconds,
    updated_at: UnixMilliseconds,
}

impl EntityTimestamps {
    // Creates one timestamp pair whose update cannot precede creation.
    pub fn new(
        created_at: UnixMilliseconds,
        updated_at: UnixMilliseconds,
    ) -> Result<Self, InterfaceError> {
        if updated_at < created_at {
            return Err(InterfaceError::new(
                "entity timestamps",
                "updated timestamp cannot precede creation",
            ));
        }
        Ok(Self {
            created_at,
            updated_at,
        })
    }

    // Returns the entity creation timestamp.
    pub const fn created_at(self) -> UnixMilliseconds {
        self.created_at
    }

    // Returns the most recent entity update timestamp.
    pub const fn updated_at(self) -> UnixMilliseconds {
        self.updated_at
    }
}

// Stores one contiguous non-privileged port allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRange {
    base: u16,
    count: u16,
}

// Stores one non-privileged network port.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkPort(u16);

impl NetworkPort {
    // Creates one port available for managed runtime allocation.
    pub fn new(value: u16) -> Result<Self, InterfaceError> {
        if value < 1024 {
            return Err(InterfaceError::new(
                "network port",
                "port must be between 1024 and 65535",
            ));
        }
        Ok(Self(value))
    }

    // Returns the exact network port.
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl PortRange {
    // Creates one bounded port range without reserving it.
    pub fn new(base: u16, count: u16) -> Result<Self, InterfaceError> {
        let end = u32::from(base) + u32::from(count);
        if base < 1024 || count == 0 || count > 32 || end > 65_536 {
            return Err(InterfaceError::new(
                "port range",
                "range must contain 1 to 32 ports between 1024 and 65535",
            ));
        }
        Ok(Self { base, count })
    }

    // Returns the first allocated port.
    pub const fn base(self) -> u16 {
        self.base
    }

    // Returns the number of contiguous allocated ports.
    pub const fn count(self) -> u16 {
        self.count
    }

    // Returns the final allocated port.
    pub const fn last(self) -> u16 {
        (self.base as u32 + self.count as u32 - 1) as u16
    }
}

// Identifies the transport used by one placement-group endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointScheme {
    Http,
    Https,
}

// Stores one structured endpoint without accepting user information or URL fragments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointAddress {
    scheme: EndpointScheme,
    host: NodeAddress,
    port: u16,
}

impl EndpointAddress {
    // Creates one explicit HTTP endpoint address.
    pub fn new(
        scheme: EndpointScheme,
        host: NodeAddress,
        port: u16,
    ) -> Result<Self, InterfaceError> {
        if port == 0 {
            return Err(InterfaceError::new(
                "endpoint address",
                "port must be between 1 and 65535",
            ));
        }
        Ok(Self { scheme, host, port })
    }

    // Returns the endpoint transport.
    pub const fn scheme(&self) -> EndpointScheme {
        self.scheme
    }

    // Returns the endpoint host without resolving it.
    pub const fn host(&self) -> &NodeAddress {
        &self.host
    }

    // Returns the endpoint port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

// Stores one bounded stable failure suitable for state and user presentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureDescription {
    code: TechnicalName,
    message: String,
}

impl FailureDescription {
    // Creates one bounded failure without embedding secret or multiline data.
    pub fn new(code: TechnicalName, message: &str) -> Result<Self, InterfaceError> {
        if !is_bounded_text(message, MAX_FAILURE_MESSAGE_BYTES, true) {
            return Err(InterfaceError::new(
                "failure description",
                "message must be canonical, non-empty, and at most 1024 bytes",
            ));
        }
        Ok(Self {
            code,
            message: message.to_string(),
        })
    }

    // Returns the stable machine-readable failure code.
    pub const fn code(&self) -> &TechnicalName {
        &self.code
    }

    // Returns the bounded user-facing failure message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

// Returns whether text is bounded, canonical, and free of control characters.
fn is_bounded_text(value: &str, maximum_bytes: usize, allow_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_whitespace || !value.chars().any(char::is_whitespace))
}

// Returns whether one value matches the canonical technical-name alphabet.
fn is_technical_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    valid_first
        && value.len() <= MAX_TECHNICAL_NAME_BYTES
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

// Returns whether one runtime-candidate component uses the canonical alphabet.
fn is_candidate_component(value: &str) -> bool {
    let mut bytes = value.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    valid_first
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

// Returns whether one value is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
