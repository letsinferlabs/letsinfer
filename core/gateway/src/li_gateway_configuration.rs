// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use li_core_interface::{NodeId, Sha256Digest};
use li_core_update_manager::CoreVersion;
use serde::Deserialize;

use crate::{GatewayNativeFileIo, GatewayNativeTlsFileSet};

pub const LI_GATEWAY_CONFIGURATION_SCHEMA_NAME: &str = "li_gateway_configuration";
pub const LI_GATEWAY_CONFIGURATION_SCHEMA_VERSION: u32 = 5;

const MAX_CONFIGURATION_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const MAXIMUM_QUEUE_MILLISECONDS: u64 = 5 * 60 * 1_000;
const MINIMUM_TELEMETRY_CADENCE_MILLISECONDS: u64 = 100;
const MAXIMUM_TELEMETRY_CADENCE_MILLISECONDS: u64 = 5_000;
const MAXIMUM_HEALTH_WORKERS: usize = 32;
const MAXIMUM_HEALTH_TIMEOUT_MILLISECONDS: u64 = 10_000;
const MAXIMUM_HEALTH_ACCEPT_POLL_MILLISECONDS: u64 = 1_000;
const MAXIMUM_PROTECTION_CACHE_MILLISECONDS: u64 = 60_000;

// Describes one stable redacted Gateway configuration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfigurationError {
    reason: &'static str,
}

impl GatewayConfigurationError {
    // Creates one internal stable failure without accepting source detail.
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    // Returns the stable redacted configuration failure.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for GatewayConfigurationError {
    // Presents one stable configuration failure without file or JSON detail.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for GatewayConfigurationError {}

// Selects the exact listener set owned by one Gateway process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayConfigurationMode {
    Main,
    Child,
}

// References one owner-bound configuration document outside process arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfigurationFile {
    owner_user_id: u32,
    path: PathBuf,
}

impl GatewayConfigurationFile {
    // Creates one absolute configuration reference with an externally trusted owner.
    pub fn new(owner_user_id: u32, path: PathBuf) -> Result<Self, GatewayConfigurationError> {
        if !path.is_absolute() {
            return Err(GatewayConfigurationError::new(
                "Gateway configuration file reference is invalid",
            ));
        }
        Ok(Self {
            owner_user_id,
            path,
        })
    }

    // Returns the owner identity required on the opened descriptor.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns the exact absolute configuration path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// Configures one bounded native listener without selecting its protocol surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayListenerConfiguration {
    address: SocketAddr,
    maximum_connections: usize,
}

impl GatewayListenerConfiguration {
    // Creates one IP-literal listener address under the native worker bound.
    fn new(address: &str, maximum_connections: usize) -> Result<Self, GatewayConfigurationError> {
        let address = address.parse::<SocketAddr>().map_err(|_| {
            GatewayConfigurationError::new("Gateway listener configuration is invalid")
        })?;
        if maximum_connections == 0 || maximum_connections > MAX_CONNECTIONS {
            return Err(GatewayConfigurationError::new(
                "Gateway listener configuration is invalid",
            ));
        }
        Ok(Self {
            address,
            maximum_connections,
        })
    }

    // Returns the exact IP-literal bind address.
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    // Returns the exact concurrent worker limit.
    pub const fn maximum_connections(&self) -> usize {
        self.maximum_connections
    }
}

// Configures the mandatory private listener and its exact TLS file roles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPrivateListenerConfiguration {
    listener: GatewayListenerConfiguration,
    tls_files: GatewayNativeTlsFileSet,
}

impl GatewayPrivateListenerConfiguration {
    // Returns the exact private bind and worker configuration.
    pub const fn listener(&self) -> &GatewayListenerConfiguration {
        &self.listener
    }

    // Returns the owner-bound TLS file roles loaded before listener mutation.
    pub const fn tls_files(&self) -> &GatewayNativeTlsFileSet {
        &self.tls_files
    }
}

// Configures the dedicated owner-authenticated local health endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayHealthConfiguration {
    socket_path: PathBuf,
    owner_user_id: u32,
    maximum_workers: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    accept_poll_interval: Duration,
}

// Configures the dedicated persistent owner-authenticated Node protection channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayNodeProtectionConfiguration {
    socket_path: PathBuf,
    read_timeout: Duration,
    write_timeout: Duration,
    maximum_cache_milliseconds: u64,
    poll_interval: Duration,
}

// Configures native macOS launchd observation without inventing a Watchdog authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayMacOsPlacementSafetyConfiguration {
    placement_material_root: PathBuf,
    launch_agents_root: PathBuf,
    launchctl_command: PathBuf,
    command_working_directory: PathBuf,
    lease_milliseconds: u64,
}

impl GatewayMacOsPlacementSafetyConfiguration {
    // Returns the exact committed placement-material root.
    pub fn placement_material_root(&self) -> &Path {
        &self.placement_material_root
    }

    // Returns the exact user LaunchAgents root.
    pub fn launch_agents_root(&self) -> &Path {
        &self.launch_agents_root
    }

    // Returns the exact launchctl executable.
    pub fn launchctl_command(&self) -> &Path {
        &self.launchctl_command
    }

    // Returns the exact native-command working directory.
    pub fn command_working_directory(&self) -> &Path {
        &self.command_working_directory
    }

    // Returns the bounded native observation lifetime.
    pub const fn lease_milliseconds(&self) -> u64 {
        self.lease_milliseconds
    }
}

impl GatewayNodeProtectionConfiguration {
    // Returns the exact dedicated Node-owned protection socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the complete-frame read timeout.
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // Returns the complete-frame write timeout.
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    // Returns the process-local monotonic snapshot cache bound.
    pub const fn maximum_cache_milliseconds(&self) -> u64 {
        self.maximum_cache_milliseconds
    }

    // Returns the resident Node polling cadence.
    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl GatewayHealthConfiguration {
    // Returns the exact local socket path owned by the Gateway resident.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    // Returns the only operating-system user accepted on both ends of the socket.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    // Returns the bounded number of concurrent health workers.
    pub const fn maximum_workers(&self) -> usize {
        self.maximum_workers
    }

    // Returns the per-connection complete request read bound.
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // Returns the per-connection complete response write bound.
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    // Returns the bounded interval used to make native shutdown observable.
    pub const fn accept_poll_interval(&self) -> Duration {
        self.accept_poll_interval
    }
}

// Owns one validated schema-5 Gateway process configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfiguration {
    node_id: NodeId,
    core_version: CoreVersion,
    core_source_identity: Sha256Digest,
    mode: GatewayConfigurationMode,
    health: GatewayHealthConfiguration,
    node_protection: Option<GatewayNodeProtectionConfiguration>,
    macos_placement_safety: Option<GatewayMacOsPlacementSafetyConfiguration>,
    public_listener: Option<GatewayListenerConfiguration>,
    private_listener: GatewayPrivateListenerConfiguration,
    node_socket_path: PathBuf,
    telemetry_file: PathBuf,
    telemetry_cadence: Duration,
    maximum_queue_milliseconds: u64,
}

impl GatewayConfiguration {
    // Loads one bounded owner-only no-follow JSON document and validates every field.
    pub fn load(
        file: &GatewayConfigurationFile,
        io: &dyn GatewayNativeFileIo,
    ) -> Result<Self, GatewayConfigurationError> {
        let observation = io
            .read_no_follow(file.path(), MAX_CONFIGURATION_BYTES)
            .map_err(|_| {
                GatewayConfigurationError::new("Gateway configuration file is unavailable")
            })?;
        if observation.owner_user_id() != file.owner_user_id()
            || observation.mode() != 0o600
            || observation.link_count() != 1
            || observation.bytes().is_empty()
        {
            return Err(GatewayConfigurationError::new(
                "Gateway configuration file metadata is unsafe",
            ));
        }
        let document = serde_json::from_slice::<GatewayConfigurationDocument>(observation.bytes())
            .map_err(|_| {
                GatewayConfigurationError::new("Gateway configuration document is invalid")
            })?;
        Self::from_document(file.owner_user_id(), document)
    }

    // Validates schema identity, role shape, addresses, bounds, and TLS path roles.
    fn from_document(
        owner_user_id: u32,
        document: GatewayConfigurationDocument,
    ) -> Result<Self, GatewayConfigurationError> {
        if document.schema.name != LI_GATEWAY_CONFIGURATION_SCHEMA_NAME
            || document.schema.version != LI_GATEWAY_CONFIGURATION_SCHEMA_VERSION
        {
            return Err(GatewayConfigurationError::new(
                "Gateway configuration schema is unsupported",
            ));
        }
        let mode = match document.mode.as_str() {
            "main" => GatewayConfigurationMode::Main,
            "child" => GatewayConfigurationMode::Child,
            _ => {
                return Err(GatewayConfigurationError::new(
                    "Gateway configuration mode is invalid",
                ));
            }
        };
        let node_id = NodeId::parse(&document.node_id)
            .map_err(|_| GatewayConfigurationError::new("Gateway resident identity is invalid"))?;
        let core_version = CoreVersion::parse(&document.core_release)
            .map_err(|_| GatewayConfigurationError::new("Gateway resident identity is invalid"))?;
        let core_source_identity = Sha256Digest::parse(&document.core_source_identity)
            .map_err(|_| GatewayConfigurationError::new("Gateway resident identity is invalid"))?;
        let health = document.health.validate(owner_user_id)?;
        let node_protection = document
            .node_protection
            .map(GatewayNodeProtectionConfigurationDocument::validate)
            .transpose()?;
        let macos_placement_safety = document
            .macos_placement_safety
            .map(GatewayMacOsPlacementSafetyConfigurationDocument::validate)
            .transpose()?;
        if node_protection.is_some() == macos_placement_safety.is_some() {
            return Err(GatewayConfigurationError::new(
                "Gateway placement safety selection is invalid",
            ));
        }
        if node_protection
            .as_ref()
            .is_some_and(|protection| protection.socket_path() == health.socket_path())
        {
            return Err(GatewayConfigurationError::new(
                "Gateway local socket paths are ambiguous",
            ));
        }
        let public_listener = document
            .public_listener
            .map(GatewayListenerConfigurationDocument::validate)
            .transpose()?;
        if (mode == GatewayConfigurationMode::Main) != public_listener.is_some() {
            return Err(GatewayConfigurationError::new(
                "Gateway configuration listener set does not match its mode",
            ));
        }
        let private_listener = document.private_listener.validate(owner_user_id)?;
        if public_listener
            .as_ref()
            .is_some_and(|public| public.address() == private_listener.listener().address())
        {
            return Err(GatewayConfigurationError::new(
                "Gateway listener addresses are ambiguous",
            ));
        }
        let runtime = document.runtime.validate()?;
        if runtime.node_socket_path == *health.socket_path()
            || node_protection
                .as_ref()
                .is_some_and(|protection| protection.socket_path() == runtime.node_socket_path)
        {
            return Err(GatewayConfigurationError::new(
                "Gateway local socket paths are ambiguous",
            ));
        }
        Ok(Self {
            node_id,
            core_version,
            core_source_identity,
            mode,
            health,
            node_protection,
            macos_placement_safety,
            public_listener,
            private_listener,
            node_socket_path: runtime.node_socket_path,
            telemetry_file: runtime.telemetry_file,
            telemetry_cadence: runtime.telemetry_cadence,
            maximum_queue_milliseconds: runtime.maximum_queue_milliseconds,
        })
    }

    // Returns whether this process is the main or a child.
    pub const fn mode(&self) -> GatewayConfigurationMode {
        self.mode
    }

    // Returns the exact local Node identity this Gateway must serve.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact Core release executing this Gateway.
    pub const fn core_version(&self) -> &CoreVersion {
        &self.core_version
    }

    // Returns the immutable Core source-manifest identity executing this Gateway.
    pub const fn core_source_identity(&self) -> &Sha256Digest {
        &self.core_source_identity
    }

    // Returns the dedicated owner-local health endpoint configuration.
    pub const fn health(&self) -> &GatewayHealthConfiguration {
        &self.health
    }

    // Returns the dedicated persistent Node protection channel configuration.
    pub const fn node_protection(&self) -> Option<&GatewayNodeProtectionConfiguration> {
        self.node_protection.as_ref()
    }

    // Returns native macOS launchd safety only when explicitly configured.
    pub const fn macos_placement_safety(
        &self,
    ) -> Option<&GatewayMacOsPlacementSafetyConfiguration> {
        self.macos_placement_safety.as_ref()
    }

    // Returns the mandatory main-only public listener when configured.
    pub const fn public_listener(&self) -> Option<&GatewayListenerConfiguration> {
        self.public_listener.as_ref()
    }

    // Returns the mandatory private listener shared by both modes.
    pub const fn private_listener(&self) -> &GatewayPrivateListenerConfiguration {
        &self.private_listener
    }

    // Returns the dedicated owner-UID local Node endpoint used for every state capability.
    pub fn node_socket_path(&self) -> &Path {
        &self.node_socket_path
    }

    // Returns the stable Watchdog-compatible telemetry publication path.
    pub fn telemetry_file(&self) -> &Path {
        &self.telemetry_file
    }

    // Returns the fixed periodic telemetry publication cadence.
    pub const fn telemetry_cadence(&self) -> Duration {
        self.telemetry_cadence
    }

    // Returns the bounded duration one inference request may remain queued.
    pub const fn maximum_queue_milliseconds(&self) -> u64 {
        self.maximum_queue_milliseconds
    }
}

// Decodes only the exact schema-5 root field set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayConfigurationDocument {
    schema: GatewayConfigurationSchemaDocument,
    node_id: String,
    core_release: String,
    core_source_identity: String,
    mode: String,
    health: GatewayHealthConfigurationDocument,
    node_protection: Option<GatewayNodeProtectionConfigurationDocument>,
    macos_placement_safety: Option<GatewayMacOsPlacementSafetyConfigurationDocument>,
    runtime: GatewayRuntimeConfigurationDocument,
    public_listener: Option<GatewayListenerConfigurationDocument>,
    private_listener: GatewayPrivateListenerConfigurationDocument,
}

// Decodes every explicit persistent Node protection channel bound.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayNodeProtectionConfigurationDocument {
    socket_path: String,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    maximum_cache_milliseconds: u64,
    poll_interval_milliseconds: u64,
}

impl GatewayNodeProtectionConfigurationDocument {
    // Validates one explicit socket and the same transport/cache bounds used at runtime.
    fn validate(self) -> Result<GatewayNodeProtectionConfiguration, GatewayConfigurationError> {
        if self.read_timeout_milliseconds == 0
            || self.read_timeout_milliseconds > MAXIMUM_HEALTH_TIMEOUT_MILLISECONDS
            || self.write_timeout_milliseconds == 0
            || self.write_timeout_milliseconds > MAXIMUM_HEALTH_TIMEOUT_MILLISECONDS
            || self.maximum_cache_milliseconds == 0
            || self.maximum_cache_milliseconds > MAXIMUM_PROTECTION_CACHE_MILLISECONDS
            || self.poll_interval_milliseconds == 0
            || self
                .poll_interval_milliseconds
                .checked_mul(2)
                .is_none_or(|margin| margin >= self.maximum_cache_milliseconds)
        {
            return Err(GatewayConfigurationError::new(
                "Gateway Node protection configuration is invalid",
            ));
        }
        Ok(GatewayNodeProtectionConfiguration {
            socket_path: absolute_normal_path(&self.socket_path)?,
            read_timeout: Duration::from_millis(self.read_timeout_milliseconds),
            write_timeout: Duration::from_millis(self.write_timeout_milliseconds),
            maximum_cache_milliseconds: self.maximum_cache_milliseconds,
            poll_interval: Duration::from_millis(self.poll_interval_milliseconds),
        })
    }
}

// Decodes one explicit macOS launchd/material observation contract.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayMacOsPlacementSafetyConfigurationDocument {
    placement_material_root: String,
    launch_agents_root: String,
    launchctl_command: String,
    command_working_directory: String,
    lease_milliseconds: u64,
}

impl GatewayMacOsPlacementSafetyConfigurationDocument {
    // Validates every native path and the same lease bound enforced by Gateway policy.
    fn validate(
        self,
    ) -> Result<GatewayMacOsPlacementSafetyConfiguration, GatewayConfigurationError> {
        let placement_material_root = absolute_normal_path(&self.placement_material_root)?;
        let launch_agents_root = absolute_normal_path(&self.launch_agents_root)?;
        let launchctl_command = absolute_normal_path(&self.launchctl_command)?;
        let command_working_directory = absolute_normal_path(&self.command_working_directory)?;
        if placement_material_root
            .file_name()
            .and_then(|value| value.to_str())
            != Some("placement_material")
            || launch_agents_root
                .file_name()
                .and_then(|value| value.to_str())
                != Some("LaunchAgents")
            || launchctl_command
                .file_name()
                .and_then(|value| value.to_str())
                != Some("launchctl")
            || self.lease_milliseconds == 0
            || self.lease_milliseconds > MAXIMUM_PROTECTION_CACHE_MILLISECONDS
        {
            return Err(GatewayConfigurationError::new(
                "Gateway macOS placement safety configuration is invalid",
            ));
        }
        Ok(GatewayMacOsPlacementSafetyConfiguration {
            placement_material_root,
            launch_agents_root,
            launchctl_command,
            command_working_directory,
            lease_milliseconds: self.lease_milliseconds,
        })
    }
}

// Decodes the complete local health endpoint without accepting implicit native defaults.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayHealthConfigurationDocument {
    socket_path: String,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

impl GatewayHealthConfigurationDocument {
    // Validates one owner-bound local endpoint and all of its lifecycle bounds.
    fn validate(
        self,
        owner_user_id: u32,
    ) -> Result<GatewayHealthConfiguration, GatewayConfigurationError> {
        let socket_path = absolute_normal_path(&self.socket_path)?;
        if self.maximum_workers == 0
            || self.maximum_workers > MAXIMUM_HEALTH_WORKERS
            || self.read_timeout_milliseconds == 0
            || self.read_timeout_milliseconds > MAXIMUM_HEALTH_TIMEOUT_MILLISECONDS
            || self.write_timeout_milliseconds == 0
            || self.write_timeout_milliseconds > MAXIMUM_HEALTH_TIMEOUT_MILLISECONDS
            || self.accept_poll_interval_milliseconds == 0
            || self.accept_poll_interval_milliseconds > MAXIMUM_HEALTH_ACCEPT_POLL_MILLISECONDS
        {
            return Err(GatewayConfigurationError::new(
                "Gateway health configuration is invalid",
            ));
        }
        Ok(GatewayHealthConfiguration {
            socket_path,
            owner_user_id,
            maximum_workers: self.maximum_workers,
            read_timeout: Duration::from_millis(self.read_timeout_milliseconds),
            write_timeout: Duration::from_millis(self.write_timeout_milliseconds),
            accept_poll_interval: Duration::from_millis(self.accept_poll_interval_milliseconds),
        })
    }
}

// Decodes only the exact nested schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayConfigurationSchemaDocument {
    name: String,
    version: u32,
}

// Decodes one exact listener field set before semantic address validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayListenerConfigurationDocument {
    address: String,
    maximum_connections: usize,
}

impl GatewayListenerConfigurationDocument {
    // Validates one decoded listener without accepting DNS or unbounded workers.
    fn validate(self) -> Result<GatewayListenerConfiguration, GatewayConfigurationError> {
        GatewayListenerConfiguration::new(&self.address, self.maximum_connections)
    }
}

// Decodes one exact private listener plus TLS role set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayPrivateListenerConfigurationDocument {
    address: String,
    maximum_connections: usize,
    tls: GatewayTlsFileConfigurationDocument,
}

impl GatewayPrivateListenerConfigurationDocument {
    // Validates one private listener and binds every TLS file to the trusted owner.
    fn validate(
        self,
        owner_user_id: u32,
    ) -> Result<GatewayPrivateListenerConfiguration, GatewayConfigurationError> {
        let listener = GatewayListenerConfiguration::new(&self.address, self.maximum_connections)?;
        let paths = [
            self.tls.server_certificate_file.as_str(),
            self.tls.server_private_key_file.as_str(),
            self.tls.client_ca_file.as_str(),
            self.tls.client_certificate_file.as_str(),
        ];
        if paths
            .iter()
            .any(|path| path.len() > MAX_PATH_BYTES || path.contains('\0'))
        {
            return Err(GatewayConfigurationError::new(
                "Gateway private TLS configuration is invalid",
            ));
        }
        let tls_files = GatewayNativeTlsFileSet::new(
            owner_user_id,
            PathBuf::from(self.tls.server_certificate_file),
            PathBuf::from(self.tls.server_private_key_file),
            PathBuf::from(self.tls.client_ca_file),
            PathBuf::from(self.tls.client_certificate_file),
        )
        .map_err(|_| {
            GatewayConfigurationError::new("Gateway private TLS configuration is invalid")
        })?;
        Ok(GatewayPrivateListenerConfiguration {
            listener,
            tls_files,
        })
    }
}

// Decodes only the four distinct absolute TLS file roles.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayTlsFileConfigurationDocument {
    server_certificate_file: String,
    server_private_key_file: String,
    client_ca_file: String,
    client_certificate_file: String,
}

// Decodes only native process dependencies shared by both Gateway modes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayRuntimeConfigurationDocument {
    node_socket_path: String,
    telemetry_file: String,
    telemetry_cadence_milliseconds: u64,
    maximum_queue_milliseconds: u64,
}

// Carries validated runtime dependencies without exposing JSON representation.
struct GatewayRuntimeConfiguration {
    node_socket_path: PathBuf,
    telemetry_file: PathBuf,
    telemetry_cadence: Duration,
    maximum_queue_milliseconds: u64,
}

impl GatewayRuntimeConfigurationDocument {
    // Validates every absolute runtime path and bounded process timing input.
    fn validate(self) -> Result<GatewayRuntimeConfiguration, GatewayConfigurationError> {
        let node_socket_path = absolute_normal_path(&self.node_socket_path)?;
        let telemetry_file = absolute_normal_path(&self.telemetry_file)?;
        if node_socket_path == telemetry_file
            || !(MINIMUM_TELEMETRY_CADENCE_MILLISECONDS..=MAXIMUM_TELEMETRY_CADENCE_MILLISECONDS)
                .contains(&self.telemetry_cadence_milliseconds)
            || self.maximum_queue_milliseconds > MAXIMUM_QUEUE_MILLISECONDS
        {
            return Err(GatewayConfigurationError::new(
                "Gateway runtime configuration is invalid",
            ));
        }
        Ok(GatewayRuntimeConfiguration {
            node_socket_path,
            telemetry_file,
            telemetry_cadence: Duration::from_millis(self.telemetry_cadence_milliseconds),
            maximum_queue_milliseconds: self.maximum_queue_milliseconds,
        })
    }
}

// Parses one traversal-free absolute path without consulting native filesystem state.
fn absolute_normal_path(value: &str) -> Result<PathBuf, GatewayConfigurationError> {
    let path = PathBuf::from(value);
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.chars().any(char::is_control)
        || !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(GatewayConfigurationError::new(
            "Gateway runtime configuration is invalid",
        ));
    }
    Ok(path)
}
