// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use li_core_interface::{NodeId, Sha256Digest};

use crate::{WatchdogError, WatchdogSafetyThresholds};

pub const WATCHDOG_CONFIGURATION_SCHEMA: &str = "li_watchdog_configuration";
pub const WATCHDOG_CONFIGURATION_VERSION: u32 = 2;
pub const WATCHDOG_CONFIGURATION_MAX_BYTES: usize = 65_536;
const WATCHDOG_CONFIGURATION_PATH_MAX_BYTES: usize = 4_095;
const WATCHDOG_CONFIGURATION_MAX_CONTROLLERS: usize = 16;

// Identifies the required concrete GPU observation provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogGpuProviderKind {
    Nvml,
}

// Identifies the required exact gateway telemetry provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogGatewayCounterProviderKind {
    GatewayTelemetryVersionTwo,
}

// Stores the complete normalized version-one resident configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogConfiguration {
    installation_id: String,
    node_id: NodeId,
    core_release: String,
    core_source_identity: Sha256Digest,
    listen_address: IpAddr,
    listen_port: u16,
    node_protection: WatchdogNodeProtectionConfiguration,
    paths: NormalizedConfigurationPaths,
    sample_interval_milliseconds: u32,
    flush_interval_milliseconds: u32,
    maximum_controllers: usize,
    gpu_provider: WatchdogGpuProviderKind,
    gateway_counter_provider: WatchdogGatewayCounterProviderKind,
    thresholds: WatchdogSafetyThresholds,
}

impl WatchdogConfiguration {
    // Parses one exact closed JSON configuration without defaults or ignored fields.
    pub fn parse(source: &[u8]) -> Result<Self, WatchdogError> {
        if source.is_empty()
            || source.len() > WATCHDOG_CONFIGURATION_MAX_BYTES
            || source.contains(&0)
        {
            return Err(configuration_error("configuration framing is invalid"));
        }
        let document: ConfigurationDocument = serde_json::from_slice(source)
            .map_err(|_| configuration_error("configuration JSON is invalid"))?;
        if document.schema.name != WATCHDOG_CONFIGURATION_SCHEMA
            || document.schema.version != WATCHDOG_CONFIGURATION_VERSION
            || !is_lower_hex(&document.installation_id, 64)
            || document.core_release.is_empty()
            || document.core_release.len() > 127
            || document.core_release.chars().any(char::is_control)
            || document.core_release.chars().any(char::is_whitespace)
            || document.listener.port == 0
        {
            return Err(configuration_error("configuration identity is unsupported"));
        }
        let paths = document.paths.normalized_paths()?;
        paths.validate_distinct()?;
        let node_protection = document.node_protection.into_configuration()?;
        if paths.contains(node_protection.socket_path()) {
            return Err(configuration_error(
                "Node protection socket path is ambiguous",
            ));
        }
        let cadence = document.cadence;
        if cadence.sample_interval_milliseconds != 1_000
            || !(cadence.sample_interval_milliseconds..=60_000)
                .contains(&cadence.flush_interval_milliseconds)
            || cadence.flush_interval_milliseconds / cadence.sample_interval_milliseconds >= 64
            || !(1..=WATCHDOG_CONFIGURATION_MAX_CONTROLLERS).contains(&document.maximum_controllers)
        {
            return Err(configuration_error(
                "resident timing or controller bounds are invalid",
            ));
        }
        let gpu_provider = match document.providers.gpu.as_str() {
            "nvml" => WatchdogGpuProviderKind::Nvml,
            _ => return Err(configuration_error("GPU provider is unsupported")),
        };
        let gateway_counter_provider = match document.providers.gateway_counters.as_str() {
            "gateway_telemetry_v2" => {
                WatchdogGatewayCounterProviderKind::GatewayTelemetryVersionTwo
            }
            _ => {
                return Err(configuration_error(
                    "gateway counter provider is unsupported",
                ))
            }
        };
        let thresholds = document.thresholds.into_thresholds()?;
        Ok(Self {
            installation_id: document.installation_id,
            node_id: NodeId::parse(&document.node_id)
                .map_err(|_| configuration_error("Node identity is invalid"))?,
            core_release: document.core_release,
            core_source_identity: Sha256Digest::parse(&document.core_source_identity)
                .map_err(|_| configuration_error("Core source identity is invalid"))?,
            listen_address: document.listener.address,
            listen_port: document.listener.port,
            node_protection,
            paths,
            sample_interval_milliseconds: cadence.sample_interval_milliseconds,
            flush_interval_milliseconds: cadence.flush_interval_milliseconds,
            maximum_controllers: document.maximum_controllers,
            gpu_provider,
            gateway_counter_provider,
            thresholds,
        })
    }

    // Returns the installation identity shared by public state and controller trust.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    // Returns the exact local Node identity whose placement state is authoritative.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the immutable Core release identity exposed by protocol status.
    pub fn core_release(&self) -> &str {
        &self.core_release
    }

    // Returns the immutable Core source manifest identity executed by this resident.
    pub const fn core_source_identity(&self) -> &Sha256Digest {
        &self.core_source_identity
    }

    // Returns the normalized bind address.
    pub const fn listen_address(&self) -> IpAddr {
        self.listen_address
    }

    // Returns the normalized bind port.
    pub const fn listen_port(&self) -> u16 {
        self.listen_port
    }

    // Returns the dedicated persistent Watchdog-to-Node protection channel.
    pub const fn node_protection(&self) -> &WatchdogNodeProtectionConfiguration {
        &self.node_protection
    }

    // Returns the exact resident sampling interval.
    pub const fn sample_interval_milliseconds(&self) -> u32 {
        self.sample_interval_milliseconds
    }

    // Returns the exact durable flush interval.
    pub const fn flush_interval_milliseconds(&self) -> u32 {
        self.flush_interval_milliseconds
    }

    // Returns the bounded authenticated-controller capacity.
    pub const fn maximum_controllers(&self) -> usize {
        self.maximum_controllers
    }

    // Returns the required concrete GPU observation provider.
    pub const fn gpu_provider(&self) -> WatchdogGpuProviderKind {
        self.gpu_provider
    }

    // Returns the required exact gateway telemetry provider.
    pub const fn gateway_counter_provider(&self) -> WatchdogGatewayCounterProviderKind {
        self.gateway_counter_provider
    }

    // Returns the complete runtime-declared protection thresholds.
    pub const fn thresholds(&self) -> WatchdogSafetyThresholds {
        self.thresholds
    }

    // Returns the private Watchdog storage root.
    pub fn data_directory(&self) -> &Path {
        &self.paths.data_directory
    }

    // Returns the owner-only server certificate path.
    pub fn server_certificate_path(&self) -> &Path {
        &self.paths.server_certificate_path
    }

    // Returns the owner-only server private-key path.
    pub fn server_private_key_path(&self) -> &Path {
        &self.paths.server_private_key_path
    }

    // Returns the owner-only controller CA path.
    pub fn controller_ca_path(&self) -> &Path {
        &self.paths.controller_ca_path
    }

    // Returns the owner-only controller allowlist path re-read during safe reload.
    pub fn controller_allowlist_path(&self) -> &Path {
        &self.paths.controller_allowlist_path
    }

    // Returns the restart-safe controller registry snapshot path.
    pub fn controller_snapshot_path(&self) -> &Path {
        &self.paths.controller_snapshot_path
    }

    // Returns the closed public state path.
    pub fn site_state_path(&self) -> &Path {
        &self.paths.site_state_path
    }

    // Returns the exact gateway telemetry-v2 snapshot path.
    pub fn gateway_metrics_path(&self) -> &Path {
        &self.paths.gateway_metrics_path
    }

    // Returns the private protected-placement descriptor root.
    pub fn protection_root_path(&self) -> &Path {
        &self.paths.protection_root_path
    }

    // Returns the shared Node-owned durable database path.
    pub fn node_database_path(&self) -> &Path {
        &self.paths.node_database_path
    }

    // Returns the immutable runtime-installation root used for verified manifests.
    pub fn runtime_installation_root(&self) -> &Path {
        &self.paths.runtime_installation_root
    }

    // Returns the mutable runtime cache root declared to verified manifests.
    pub fn runtime_cache_root(&self) -> &Path {
        &self.paths.runtime_cache_root
    }
}

// Decodes only the declared top-level version-one JSON fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationDocument {
    schema: ConfigurationSchema,
    installation_id: String,
    node_id: String,
    core_release: String,
    core_source_identity: String,
    listener: ConfigurationListener,
    node_protection: ConfigurationNodeProtection,
    paths: ConfigurationPaths,
    cadence: ConfigurationCadence,
    maximum_controllers: usize,
    providers: ConfigurationProviders,
    thresholds: ConfigurationThresholds,
}

// Stores the complete bounded owner-local Node protection client contract.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationNodeProtection {
    socket_path: String,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
}

// Holds one fully validated Watchdog-to-Node protection channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogNodeProtectionConfiguration {
    socket_path: PathBuf,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl ConfigurationNodeProtection {
    // Normalizes one explicit client channel and rejects absent or excessive deadlines.
    fn into_configuration(self) -> Result<WatchdogNodeProtectionConfiguration, WatchdogError> {
        if self.read_timeout_milliseconds == 0
            || self.read_timeout_milliseconds > 60_000
            || self.write_timeout_milliseconds == 0
            || self.write_timeout_milliseconds > 60_000
        {
            return Err(configuration_error("Node protection timing is invalid"));
        }
        Ok(WatchdogNodeProtectionConfiguration {
            socket_path: normalized_path(&self.socket_path)?,
            read_timeout: Duration::from_millis(self.read_timeout_milliseconds),
            write_timeout: Duration::from_millis(self.write_timeout_milliseconds),
        })
    }
}

impl WatchdogNodeProtectionConfiguration {
    // Returns the exact dedicated Node-owned socket.
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
}

// Decodes the exact nested configuration schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationSchema {
    name: String,
    version: u32,
}

// Decodes one literal-IP listener identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationListener {
    address: IpAddr,
    port: u16,
}

// Decodes every required absolute native path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationPaths {
    data_directory: String,
    server_certificate_path: String,
    server_private_key_path: String,
    controller_ca_path: String,
    controller_allowlist_path: String,
    controller_snapshot_path: String,
    site_state_path: String,
    gateway_metrics_path: String,
    protection_root_path: String,
    node_database_path: String,
    runtime_installation_root: String,
    runtime_cache_root: String,
}

impl ConfigurationPaths {
    // Normalizes every external path once at the configuration boundary.
    fn normalized_paths(self) -> Result<NormalizedConfigurationPaths, WatchdogError> {
        Ok(NormalizedConfigurationPaths {
            data_directory: normalized_path(&self.data_directory)?,
            server_certificate_path: normalized_path(&self.server_certificate_path)?,
            server_private_key_path: normalized_path(&self.server_private_key_path)?,
            controller_ca_path: normalized_path(&self.controller_ca_path)?,
            controller_allowlist_path: normalized_path(&self.controller_allowlist_path)?,
            controller_snapshot_path: normalized_path(&self.controller_snapshot_path)?,
            site_state_path: normalized_path(&self.site_state_path)?,
            gateway_metrics_path: normalized_path(&self.gateway_metrics_path)?,
            protection_root_path: normalized_path(&self.protection_root_path)?,
            node_database_path: normalized_path(&self.node_database_path)?,
            runtime_installation_root: normalized_path(&self.runtime_installation_root)?,
            runtime_cache_root: normalized_path(&self.runtime_cache_root)?,
        })
    }
}

// Stores named normalized paths without positional meaning inside the process.
#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedConfigurationPaths {
    data_directory: PathBuf,
    server_certificate_path: PathBuf,
    server_private_key_path: PathBuf,
    controller_ca_path: PathBuf,
    controller_allowlist_path: PathBuf,
    controller_snapshot_path: PathBuf,
    site_state_path: PathBuf,
    gateway_metrics_path: PathBuf,
    protection_root_path: PathBuf,
    node_database_path: PathBuf,
    runtime_installation_root: PathBuf,
    runtime_cache_root: PathBuf,
}

impl NormalizedConfigurationPaths {
    // Returns whether one additional native path aliases any Watchdog-owned role.
    fn contains(&self, candidate: &Path) -> bool {
        [
            self.data_directory.as_path(),
            self.server_certificate_path.as_path(),
            self.server_private_key_path.as_path(),
            self.controller_ca_path.as_path(),
            self.controller_allowlist_path.as_path(),
            self.controller_snapshot_path.as_path(),
            self.site_state_path.as_path(),
            self.gateway_metrics_path.as_path(),
            self.protection_root_path.as_path(),
            self.node_database_path.as_path(),
            self.runtime_installation_root.as_path(),
            self.runtime_cache_root.as_path(),
        ]
        .contains(&candidate)
    }

    // Rejects path aliasing between every independently owned native artifact.
    fn validate_distinct(&self) -> Result<(), WatchdogError> {
        let paths = [
            self.data_directory.as_path(),
            self.server_certificate_path.as_path(),
            self.server_private_key_path.as_path(),
            self.controller_ca_path.as_path(),
            self.controller_allowlist_path.as_path(),
            self.controller_snapshot_path.as_path(),
            self.site_state_path.as_path(),
            self.gateway_metrics_path.as_path(),
            self.protection_root_path.as_path(),
            self.node_database_path.as_path(),
            self.runtime_installation_root.as_path(),
            self.runtime_cache_root.as_path(),
        ];
        for left in 0..paths.len() {
            for right in (left + 1)..paths.len() {
                if paths[left] == paths[right] {
                    return Err(configuration_error("configuration paths must be distinct"));
                }
            }
        }
        Ok(())
    }
}

// Decodes exact bounded sample and durability cadences.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationCadence {
    sample_interval_milliseconds: u32,
    flush_interval_milliseconds: u32,
}

// Decodes explicit providers without turning absence into unsupported telemetry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationProviders {
    gpu: String,
    gateway_counters: String,
}

// Decodes every required safety threshold without native defaults.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationThresholds {
    warning_available_bytes: u64,
    graceful_available_bytes: u64,
    emergency_available_bytes: u64,
    swap_stop_bytes: u64,
    psi_some_microseconds: u64,
    psi_full_microseconds: u64,
    state_failures: u32,
    containment_grace_milliseconds: u32,
}

impl ConfigurationThresholds {
    // Converts the JSON projection through the existing closed safety contract.
    fn into_thresholds(self) -> Result<WatchdogSafetyThresholds, WatchdogError> {
        WatchdogSafetyThresholds::new(
            self.warning_available_bytes,
            self.graceful_available_bytes,
            self.emergency_available_bytes,
            self.swap_stop_bytes,
            self.psi_some_microseconds,
            self.psi_full_microseconds,
            self.state_failures,
            self.containment_grace_milliseconds,
        )
    }
}

// Captures stable descriptor metadata and bytes from one injected read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogConfigurationFile {
    bytes: Vec<u8>,
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    is_stable: bool,
}

impl WatchdogConfigurationFile {
    // Creates one exact configuration-file observation for system or mock providers.
    pub fn new(
        bytes: Vec<u8>,
        owner_user_id: u32,
        mode: u32,
        link_count: u64,
        is_regular_file: bool,
        is_stable: bool,
    ) -> Self {
        Self {
            bytes,
            owner_user_id,
            mode,
            link_count,
            is_regular_file,
            is_stable,
        }
    }
}

// Reads an already-selected configuration without owning policy or parsing.
pub trait WatchdogConfigurationFileProvider: Send + Sync {
    // Returns bounded bytes and stable descriptor metadata for one path.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogConfigurationFile, WatchdogError>;
}

// Owns strict configuration file validation and normalized parsing.
pub struct WatchdogConfigurationLoader {
    path: PathBuf,
    owner_user_id: u32,
    provider: Box<dyn WatchdogConfigurationFileProvider>,
}

impl WatchdogConfigurationLoader {
    // Creates one loader only for a normalized absolute configuration path.
    pub fn new(
        path: PathBuf,
        owner_user_id: u32,
        provider: Box<dyn WatchdogConfigurationFileProvider>,
    ) -> Result<Self, WatchdogError> {
        validate_normalized_path(&path)?;
        Ok(Self {
            path,
            owner_user_id,
            provider,
        })
    }

    // Reads and validates the exact owner-only configuration document.
    pub fn load(&self) -> Result<WatchdogConfiguration, WatchdogError> {
        let file = self
            .provider
            .read(&self.path, WATCHDOG_CONFIGURATION_MAX_BYTES)?;
        if file.owner_user_id != self.owner_user_id
            || file.mode != 0o600
            || file.link_count != 1
            || !file.is_regular_file
            || !file.is_stable
        {
            return Err(configuration_error("configuration file identity is unsafe"));
        }
        WatchdogConfiguration::parse(&file.bytes)
    }
}

// Reads owner-only configuration bytes through one no-follow stable descriptor.
pub struct SystemWatchdogConfigurationFileProvider;

impl WatchdogConfigurationFileProvider for SystemWatchdogConfigurationFileProvider {
    // Opens the final path without links and rejects metadata substitution or growth.
    fn read(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<WatchdogConfigurationFile, WatchdogError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| configuration_provider_error("configuration file could not be opened"))?;
        let initial = file
            .metadata()
            .map_err(|_| configuration_provider_error("configuration metadata is unavailable"))?;
        if initial.len() == 0 || initial.len() > maximum_bytes as u64 {
            return Err(configuration_provider_error(
                "configuration size is invalid",
            ));
        }
        let mut bytes = Vec::with_capacity(initial.len() as usize);
        file.by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| configuration_provider_error("configuration file could not be read"))?;
        let final_metadata = file
            .metadata()
            .map_err(|_| configuration_provider_error("configuration metadata is unavailable"))?;
        let stable =
            stable_file_identity(&initial, &final_metadata) && bytes.len() as u64 == initial.len();
        Ok(WatchdogConfigurationFile::new(
            bytes,
            initial.uid(),
            initial.mode() & 0o777,
            initial.nlink(),
            initial.file_type().is_file(),
            stable,
        ))
    }
}

// Parses and proves one absolute path already has its canonical lexical form.
fn normalized_path(value: &str) -> Result<PathBuf, WatchdogError> {
    let path = PathBuf::from(value);
    validate_normalized_path(&path)?;
    Ok(path)
}

// Rejects relative, empty, aliased, non-UTF-8, or oversized paths.
fn validate_normalized_path(path: &Path) -> Result<(), WatchdogError> {
    let value = path
        .to_str()
        .ok_or_else(|| configuration_error("configuration path is invalid"))?;
    if value.len() > WATCHDOG_CONFIGURATION_PATH_MAX_BYTES
        || value == "/"
        || value.contains("//")
        || value.ends_with('/')
        || !path.is_absolute()
        || path.components().next() != Some(Component::RootDir)
        || path
            .components()
            .skip(1)
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(configuration_error("configuration path is not normalized"));
    }
    Ok(())
}

// Returns whether one identity is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Compares descriptor identity before and after the bounded read.
fn stable_file_identity(initial: &std::fs::Metadata, final_metadata: &std::fs::Metadata) -> bool {
    initial.dev() == final_metadata.dev()
        && initial.ino() == final_metadata.ino()
        && initial.uid() == final_metadata.uid()
        && initial.mode() == final_metadata.mode()
        && initial.nlink() == final_metadata.nlink()
        && initial.len() == final_metadata.len()
        && initial.mtime() == final_metadata.mtime()
        && initial.mtime_nsec() == final_metadata.mtime_nsec()
}

// Creates one stable redacted configuration contract failure.
const fn configuration_error(reason: &'static str) -> WatchdogError {
    WatchdogError::InvalidContract { reason }
}

// Creates one stable redacted native configuration failure.
const fn configuration_provider_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("configuration", reason)
}
