// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use li_core_interface::{CpuArchitecture, CredentialId, DisplayName, NodeAddress, Sha256Digest};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};
use li_watchdog_manager::WatchdogSafetyThresholds;
use serde::Deserialize;

use crate::{
    ApplicationCoreSetup, CoreSetupBenchmarkSigningPaths, CoreSetupCliConfigurationTemplate,
    CoreSetupCompositionError, CoreSetupCompositionInput, CoreSetupCompositionRoots,
    CoreSetupConfigurationLocation, CoreSetupError, CoreSetupGatewayConfigurationTemplate,
    CoreSetupGatewayHealthInput, CoreSetupGatewayProtectionInput, CoreSetupGatewayTrustPaths,
    CoreSetupMaterialPaths, CoreSetupNetworkPlan, CoreSetupNodeBenchmarkTemplate,
    CoreSetupNodeConfigurationTemplate, CoreSetupNodeHardwareInput, CoreSetupNodeLocalApiInput,
    CoreSetupNodeModelInput, CoreSetupNodePairingPlatformInput,
    CoreSetupNodePlacementSafetyTemplate, CoreSetupNodeProtectionExecutableInput,
    CoreSetupNodeTrustPaths, CoreSetupNodeUpdateInput, CoreSetupPairingTrustPaths,
    CoreSetupPlatformInput, CoreSetupRequest, CoreSetupWatchdogConfigurationTemplate,
    CoreSetupWatchdogHealthInput, CoreSetupWatchdogTrustPaths,
};

pub const CORE_SETUP_INPUT_SCHEMA_NAME: &str = "li_core_setup_input";
pub const CORE_SETUP_INPUT_SCHEMA_VERSION: u32 = 5;
pub const MAXIMUM_CORE_SETUP_INPUT_BYTES: usize = 256 * 1024;
pub const CORE_SETUP_EXIT_COMMITTED: i32 = 0;
pub const CORE_SETUP_EXIT_SAFE_TO_ROLLBACK: i32 = 2;
pub const CORE_SETUP_EXIT_RECOVERY_REQUIRED: i32 = 3;
const MAXIMUM_GATEWAY_QUEUE_MILLISECONDS: u64 = 5 * 60 * 1_000;
const MINIMUM_NODE_DAEMON_CADENCE_MILLISECONDS: u64 = 100;
const MAXIMUM_NODE_DAEMON_CADENCE_MILLISECONDS: u64 = 300_000;
const MAXIMUM_NODE_WORKERS: usize = 64;
const MAXIMUM_NODE_TIMEOUT_MILLISECONDS: u64 = 60_000;
const MAXIMUM_ACCEPT_POLL_MILLISECONDS: u64 = 1_000;
const MINIMUM_GATEWAY_TELEMETRY_CADENCE_MILLISECONDS: u64 = 100;
const MAXIMUM_GATEWAY_TELEMETRY_CADENCE_MILLISECONDS: u64 = 5_000;
const MAXIMUM_GATEWAY_HEALTH_WORKERS: usize = 32;
const MAXIMUM_GATEWAY_HEALTH_TIMEOUT_MILLISECONDS: u64 = 10_000;
const MAXIMUM_GATEWAY_CONNECTIONS: usize = 256;
const MINIMUM_WATCHDOG_FLUSH_MILLISECONDS: u32 = 1_000;
const MAXIMUM_WATCHDOG_FLUSH_MILLISECONDS: u32 = 60_000;
const MAXIMUM_WATCHDOG_CONTROLLERS: usize = 16;
const WATCHDOG_PROTECTION_ROOT_NAME: &str = "protected-placements";
const PAIRING_TRUST_WORKSPACE_NAME: &str = "pairing_trust_staging";

// Carries the decoded production composition and its exact standalone-main request.
pub struct DecodedCoreSetupInput {
    composition: CoreSetupCompositionInput,
    request: CoreSetupRequest,
}

impl DecodedCoreSetupInput {
    // Returns the exact request for read-only inspection before production composition.
    pub const fn request(&self) -> &CoreSetupRequest {
        &self.request
    }

    // Transfers both validated values into the production application runner.
    pub fn into_parts(self) -> (CoreSetupCompositionInput, CoreSetupRequest) {
        (self.composition, self.request)
    }
}

// Names one stable process input, setup, or output boundary failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupProcessError {
    InvalidArguments,
    InputUnavailable,
    InvalidInput,
    Application(CoreSetupCompositionError),
    OutputUnavailable,
}

impl fmt::Display for CoreSetupProcessError {
    // Presents one stable redacted line without request paths, credentials, or native diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str("li_core_setup arguments are invalid"),
            Self::InputUnavailable => formatter.write_str("li_core_setup input is unavailable"),
            Self::InvalidInput => formatter.write_str("li_core_setup input is invalid"),
            Self::Application(error) => write!(formatter, "{error}"),
            Self::OutputUnavailable => formatter.write_str("li_core_setup output is unavailable"),
        }
    }
}

impl Error for CoreSetupProcessError {}

// Isolates stdin, stdout, and stderr for bounded process-contract tests.
pub trait CoreSetupProcessIo {
    // Reads at most one byte beyond the absolute input limit to prove oversize rejection.
    fn read_input(&mut self, maximum_bytes: usize) -> Result<Vec<u8>, CoreSetupProcessError>;

    // Writes exactly one successful newline-terminated result document.
    fn write_output(&mut self, bytes: &[u8]) -> Result<(), CoreSetupProcessError>;

    // Writes exactly one stable newline-terminated error line.
    fn write_error(&mut self, bytes: &[u8]) -> Result<(), CoreSetupProcessError>;
}

// Performs the native standard-stream process boundary without a shell or auxiliary files.
#[derive(Default)]
pub struct SystemCoreSetupProcessIo;

impl CoreSetupProcessIo for SystemCoreSetupProcessIo {
    // Reads one bounded standard-input document and retains one excess byte for rejection.
    fn read_input(&mut self, maximum_bytes: usize) -> Result<Vec<u8>, CoreSetupProcessError> {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(maximum_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CoreSetupProcessError::InputUnavailable)?;
        Ok(bytes)
    }

    // Writes and flushes the complete successful result to stdout.
    fn write_output(&mut self, bytes: &[u8]) -> Result<(), CoreSetupProcessError> {
        let mut output = std::io::stdout().lock();
        output
            .write_all(bytes)
            .and_then(|_| output.flush())
            .map_err(|_| CoreSetupProcessError::OutputUnavailable)
    }

    // Writes and flushes one stable error line to stderr.
    fn write_error(&mut self, bytes: &[u8]) -> Result<(), CoreSetupProcessError> {
        let mut output = std::io::stderr().lock();
        output
            .write_all(bytes)
            .and_then(|_| output.flush())
            .map_err(|_| CoreSetupProcessError::OutputUnavailable)
    }
}

// Runs the decoded application without exposing production composition to stream handling.
pub trait CoreSetupProcessApplicationRunner {
    // Composes and executes one validated request, returning only its closed JSON result.
    fn setup_json(
        &self,
        input: DecodedCoreSetupInput,
    ) -> Result<Vec<u8>, CoreSetupCompositionError>;
}

// Composes and runs the ordinary production Core setup application.
#[derive(Default)]
pub struct SystemCoreSetupProcessApplicationRunner;

impl CoreSetupProcessApplicationRunner for SystemCoreSetupProcessApplicationRunner {
    // Transfers validated input into production composition and exact request execution.
    fn setup_json(
        &self,
        input: DecodedCoreSetupInput,
    ) -> Result<Vec<u8>, CoreSetupCompositionError> {
        let (composition, request) = input.into_parts();
        ApplicationCoreSetup::compose(composition)?.setup_json(&request)
    }
}

// Runs one complete stdin-to-stdout setup process and returns its stable exit status.
pub fn run_core_setup_process(
    arguments: &[OsString],
    io: &mut dyn CoreSetupProcessIo,
    application: &dyn CoreSetupProcessApplicationRunner,
) -> i32 {
    let result = if arguments.len() == 1 {
        io.read_input(MAXIMUM_CORE_SETUP_INPUT_BYTES)
            .and_then(|bytes| decode_core_setup_input(&bytes))
            .and_then(|input| {
                application
                    .setup_json(input)
                    .map_err(CoreSetupProcessError::Application)
            })
            .and_then(|bytes| io.write_output(&bytes))
    } else {
        Err(CoreSetupProcessError::InvalidArguments)
    };
    match result {
        Ok(()) => CORE_SETUP_EXIT_COMMITTED,
        Err(error) => {
            let status = core_setup_exit_status(&error);
            let mut line = error.to_string().into_bytes();
            line.push(b'\n');
            let _ = io.write_error(&line);
            status
        }
    }
}

// Classifies only pre-dispatch rejection or a durably compensated setup as rollback-safe.
fn core_setup_exit_status(error: &CoreSetupProcessError) -> i32 {
    match error {
        CoreSetupProcessError::InvalidArguments | CoreSetupProcessError::InvalidInput => {
            CORE_SETUP_EXIT_SAFE_TO_ROLLBACK
        }
        CoreSetupProcessError::Application(CoreSetupCompositionError::Setup(
            CoreSetupError::RolledBack { .. },
        )) => CORE_SETUP_EXIT_SAFE_TO_ROLLBACK,
        CoreSetupProcessError::InputUnavailable
        | CoreSetupProcessError::Application(_)
        | CoreSetupProcessError::OutputUnavailable => CORE_SETUP_EXIT_RECOVERY_REQUIRED,
    }
}

// Decodes one complete closed UTF-8 document into production typed inputs without native work.
pub fn decode_core_setup_input(
    bytes: &[u8],
) -> Result<DecodedCoreSetupInput, CoreSetupProcessError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CORE_SETUP_INPUT_BYTES {
        return Err(CoreSetupProcessError::InvalidInput);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CoreSetupProcessError::InvalidInput)?;
    let document: InputDocument =
        serde_json::from_str(text).map_err(|_| CoreSetupProcessError::InvalidInput)?;
    document.into_input()
}

// Stores the complete version-one setup process document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDocument {
    schema: SchemaDocument,
    owner_user_id: u32,
    request: RequestDocument,
    roots: RootsDocument,
    material: MaterialDocument,
    configuration: ConfigurationDocument,
    native: NativeDocument,
}

impl InputDocument {
    // Validates cross-section platform, role, path, and trust identities before composition.
    fn into_input(self) -> Result<DecodedCoreSetupInput, CoreSetupProcessError> {
        if self.schema.name != CORE_SETUP_INPUT_SCHEMA_NAME
            || self.schema.version != CORE_SETUP_INPUT_SCHEMA_VERSION
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let (context, request) = self.request.into_request()?;
        if self.native.platform() != context.platform()
            || self.configuration.node.hardware.platform() != context.platform()
            || self.configuration.node.pairing.platform() != context.platform()
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let roots = self.roots.into_roots(self.owner_user_id)?;
        let resolved_material = self
            .material
            .into_material(context.platform(), roots.material_root())?;
        let native = self
            .native
            .into_platform(resolved_material.watchdog_health_binding.as_ref())?;
        let cli = self.configuration.cli.into_template()?;
        let node = self.configuration.node.into_template(
            context.platform(),
            native.openssl_command.clone(),
            roots.trust_workspace_root(),
        )?;
        let gateway = self.configuration.gateway.into_template()?;
        let watchdog = self
            .configuration
            .watchdog
            .map(|value| value.into_template(roots.material_root()))
            .transpose()?;
        if watchdog.is_some() != (context.platform() == CoreUpdateServicePlatform::Linux) {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let provider_identity = digest(&self.configuration.provider_identity)?;
        let composition = CoreSetupCompositionInput::new(
            context,
            self.owner_user_id,
            roots.into_composition_roots()?,
            resolved_material.paths,
            provider_identity,
            cli,
            node,
            gateway,
            watchdog,
            native.openssl_command,
            native.platform,
        )
        .map_err(|_| CoreSetupProcessError::InvalidInput)?;
        Ok(DecodedCoreSetupInput {
            composition,
            request,
        })
    }
}

// Stores one exact nested setup-input schema identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaDocument {
    name: String,
    version: u32,
}

// Selects the only supported initial node role.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RoleDocument {
    Main,
}

// Selects one supported native service platform.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PlatformDocument {
    Linux,
    Macos,
}

impl PlatformDocument {
    // Projects the wire platform onto the internal service context.
    const fn value(self) -> CoreUpdateServicePlatform {
        match self {
            Self::Linux => CoreUpdateServicePlatform::Linux,
            Self::Macos => CoreUpdateServicePlatform::Macos,
        }
    }
}

// Stores the complete immutable request and listener identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDocument {
    request_id: String,
    platform: PlatformDocument,
    role: RoleDocument,
    core_version: String,
    core_source_identity: String,
    display_name: String,
    control_address: String,
    node_private_address: String,
    gateway_private_address: String,
    gateway_public_address: Option<String>,
    watchdog_address: Option<String>,
}

impl RequestDocument {
    // Builds one standalone-main request after enforcing the platform-exact listener shape.
    fn into_request(
        self,
    ) -> Result<(CoreUpdateServiceContext, CoreSetupRequest), CoreSetupProcessError> {
        let platform = self.platform.value();
        let role = match self.role {
            RoleDocument::Main => CoreUpdateNodeRole::Main,
        };
        let context = CoreUpdateServiceContext::new(platform, role);
        let node_private = socket_address(&self.node_private_address)?;
        let gateway_private = socket_address(&self.gateway_private_address)?;
        let gateway_public = optional_socket_address(self.gateway_public_address.as_deref())?;
        let watchdog = optional_socket_address(self.watchdog_address.as_deref())?;
        let mut ports = vec![node_private.port(), gateway_private.port()];
        ports.extend(gateway_public.iter().map(SocketAddr::port));
        ports.extend(watchdog.iter().map(SocketAddr::port));
        ports.sort_unstable();
        if gateway_public.is_none()
            || watchdog.is_some() != (platform == CoreUpdateServicePlatform::Linux)
            || ports.first() == Some(&0)
            || ports.windows(2).any(|values| values[0] == values[1])
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let request = CoreSetupRequest::new(
            digest(&self.request_id)?,
            context,
            CoreInstallation::new(
                CoreVersion::parse(&self.core_version)
                    .map_err(|_| CoreSetupProcessError::InvalidInput)?,
                digest(&self.core_source_identity)?,
            ),
            DisplayName::parse(&self.display_name)
                .map_err(|_| CoreSetupProcessError::InvalidInput)?,
            NodeAddress::parse(&self.control_address)
                .map_err(|_| CoreSetupProcessError::InvalidInput)?,
            CoreSetupNetworkPlan::new(node_private, gateway_private, gateway_public, watchdog),
        );
        Ok((context, request))
    }
}

// Stores every explicit root supplied by the installer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootsDocument {
    letsinfer_home: String,
    home_directory: String,
    setup_state_directory: String,
    material_root: String,
    trust_workspace_root: String,
    configuration_directory: String,
}

// Retains parsed roots needed by both material containment and final composition.
struct ResolvedRoots {
    letsinfer_home: PathBuf,
    home_directory: PathBuf,
    setup_state_directory: PathBuf,
    material_root: PathBuf,
    trust_workspace_root: PathBuf,
    configuration: CoreSetupConfigurationLocation,
}

impl RootsDocument {
    // Parses every root once without inspecting or creating native state.
    fn into_roots(self, owner_user_id: u32) -> Result<ResolvedRoots, CoreSetupProcessError> {
        Ok(ResolvedRoots {
            letsinfer_home: normal_path(&self.letsinfer_home)?,
            home_directory: normal_path(&self.home_directory)?,
            setup_state_directory: normal_path(&self.setup_state_directory)?,
            material_root: normal_path(&self.material_root)?,
            trust_workspace_root: normal_path(&self.trust_workspace_root)?,
            configuration: CoreSetupConfigurationLocation::new(
                normal_path(&self.configuration_directory)?,
                owner_user_id,
            )
            .map_err(|_| CoreSetupProcessError::InvalidInput)?,
        })
    }
}

impl ResolvedRoots {
    // Returns the material root needed to close every private destination before composition.
    fn material_root(&self) -> &Path {
        &self.material_root
    }

    // Returns the exact root that must contain pairing's one ephemeral staging directory.
    fn trust_workspace_root(&self) -> &Path {
        &self.trust_workspace_root
    }

    // Transfers validated roots into the production composition value.
    fn into_composition_roots(self) -> Result<CoreSetupCompositionRoots, CoreSetupProcessError> {
        CoreSetupCompositionRoots::new(
            self.letsinfer_home,
            self.home_directory,
            self.setup_state_directory,
            self.material_root,
            self.trust_workspace_root,
            self.configuration,
        )
        .map_err(|_| CoreSetupProcessError::InvalidInput)
    }
}

// Stores every exact private material destination.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialDocument {
    database_file: String,
    pairing_setup_secret_file: String,
    api_key_file: String,
    benchmark_signing: BenchmarkSigningMaterialDocument,
    pairing: PairingMaterialDocument,
    node: MutualTlsMaterialDocument,
    gateway: GatewayMaterialDocument,
    watchdog: Option<WatchdogMaterialDocument>,
}

// Stores the dedicated Ed25519 benchmark-signing destination pair.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkSigningMaterialDocument {
    private_key_file: String,
    public_key_file: String,
}

// Stores the four pairing trust destinations.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingMaterialDocument {
    site_private_key_file: String,
    site_public_key_file: String,
    site_ca_certificate_file: String,
    local_control_certificate_file: String,
}

// Stores one authority, server, and ordinary client destination closure.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutualTlsMaterialDocument {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    client_certificate_file: String,
    client_private_key_file: String,
}

// Stores the Gateway authority, server, and relay-client destination closure.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayMaterialDocument {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    relay_client_certificate_file: String,
    relay_client_private_key_file: String,
}

// Stores the Linux Watchdog authority, server, controller, and allowlist destinations.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchdogMaterialDocument {
    authority_private_key_file: String,
    authority_certificate_file: String,
    server_certificate_file: String,
    server_private_key_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
    controller_allowlist_file: String,
}

// Retains the complete material paths and exact Watchdog health binding projection.
struct ResolvedMaterial {
    paths: CoreSetupMaterialPaths,
    watchdog_health_binding: Option<CoreSetupWatchdogHealthInput>,
}

impl MaterialDocument {
    // Parses, closes, and root-binds every material path before any secret generation.
    fn into_material(
        self,
        platform: CoreUpdateServicePlatform,
        material_root: &Path,
    ) -> Result<ResolvedMaterial, CoreSetupProcessError> {
        let watchdog = self
            .watchdog
            .map(WatchdogMaterialDocument::resolved)
            .transpose()?;
        if watchdog.is_some() != (platform == CoreUpdateServicePlatform::Linux) {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let watchdog_health_binding = watchdog
            .as_ref()
            .map(|value| {
                CoreSetupWatchdogHealthInput::new(
                    value.authority_certificate_file.clone(),
                    value.controller_certificate_file.clone(),
                    value.controller_private_key_file.clone(),
                )
            })
            .transpose()
            .map_err(|_| CoreSetupProcessError::InvalidInput)?;
        let benchmark_signing = CoreSetupBenchmarkSigningPaths::new(
            normal_path(&self.benchmark_signing.private_key_file)?,
            normal_path(&self.benchmark_signing.public_key_file)?,
        );
        let paths = CoreSetupMaterialPaths::new(
            normal_path(&self.database_file)?,
            normal_path(&self.pairing_setup_secret_file)?,
            normal_path(&self.api_key_file)?,
            self.pairing.into_paths()?,
            self.node.into_node_paths()?,
            self.gateway.into_paths()?,
            watchdog.map(ResolvedWatchdogMaterial::into_paths),
        )
        .and_then(|paths| paths.with_benchmark_signing(benchmark_signing))
        .map_err(|_| CoreSetupProcessError::InvalidInput)?;
        if !paths.is_contained_by(material_root) {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(ResolvedMaterial {
            paths,
            watchdog_health_binding,
        })
    }
}

impl PairingMaterialDocument {
    // Parses the exact four-file pairing trust destination set.
    fn into_paths(self) -> Result<CoreSetupPairingTrustPaths, CoreSetupProcessError> {
        Ok(CoreSetupPairingTrustPaths::new(
            normal_path(&self.site_private_key_file)?,
            normal_path(&self.site_public_key_file)?,
            normal_path(&self.site_ca_certificate_file)?,
            normal_path(&self.local_control_certificate_file)?,
        ))
    }
}

impl MutualTlsMaterialDocument {
    // Parses the complete standalone-main Node trust destination set.
    fn into_node_paths(self) -> Result<CoreSetupNodeTrustPaths, CoreSetupProcessError> {
        Ok(CoreSetupNodeTrustPaths::new(
            normal_path(&self.authority_private_key_file)?,
            normal_path(&self.authority_certificate_file)?,
            normal_path(&self.server_certificate_file)?,
            normal_path(&self.server_private_key_file)?,
            normal_path(&self.client_certificate_file)?,
            normal_path(&self.client_private_key_file)?,
        ))
    }
}

impl GatewayMaterialDocument {
    // Parses the complete standalone-main Gateway trust destination set.
    fn into_paths(self) -> Result<CoreSetupGatewayTrustPaths, CoreSetupProcessError> {
        Ok(CoreSetupGatewayTrustPaths::new(
            normal_path(&self.authority_private_key_file)?,
            normal_path(&self.authority_certificate_file)?,
            normal_path(&self.server_certificate_file)?,
            normal_path(&self.server_private_key_file)?,
            normal_path(&self.relay_client_certificate_file)?,
            normal_path(&self.relay_client_private_key_file)?,
        ))
    }
}

// Retains parsed Watchdog paths across health and material projections.
struct ResolvedWatchdogMaterial {
    authority_private_key_file: PathBuf,
    authority_certificate_file: PathBuf,
    server_certificate_file: PathBuf,
    server_private_key_file: PathBuf,
    controller_certificate_file: PathBuf,
    controller_private_key_file: PathBuf,
    controller_allowlist_file: PathBuf,
}

impl WatchdogMaterialDocument {
    // Parses the complete Linux-only Watchdog trust destination set once.
    fn resolved(self) -> Result<ResolvedWatchdogMaterial, CoreSetupProcessError> {
        Ok(ResolvedWatchdogMaterial {
            authority_private_key_file: normal_path(&self.authority_private_key_file)?,
            authority_certificate_file: normal_path(&self.authority_certificate_file)?,
            server_certificate_file: normal_path(&self.server_certificate_file)?,
            server_private_key_file: normal_path(&self.server_private_key_file)?,
            controller_certificate_file: normal_path(&self.controller_certificate_file)?,
            controller_private_key_file: normal_path(&self.controller_private_key_file)?,
            controller_allowlist_file: normal_path(&self.controller_allowlist_file)?,
        })
    }
}

impl ResolvedWatchdogMaterial {
    // Transfers parsed paths into the production Linux Watchdog material closure.
    fn into_paths(self) -> CoreSetupWatchdogTrustPaths {
        CoreSetupWatchdogTrustPaths::new(
            self.authority_private_key_file,
            self.authority_certificate_file,
            self.server_certificate_file,
            self.server_private_key_file,
            self.controller_certificate_file,
            self.controller_private_key_file,
            self.controller_allowlist_file,
        )
    }
}

// Stores every non-material resident configuration template input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationDocument {
    provider_identity: String,
    cli: CliConfigurationDocument,
    node: NodeConfigurationDocument,
    gateway: GatewayConfigurationDocument,
    watchdog: Option<WatchdogConfigurationDocument>,
}

// Stores every explicit nonresident native CLI client input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliConfigurationDocument {
    entropy_source: String,
    launcher_file: String,
    privilege_command: Option<String>,
    timeout_milliseconds: u64,
    maximum_response_bytes: usize,
}

impl CliConfigurationDocument {
    // Validates one bounded client template without consulting the active host.
    fn into_template(self) -> Result<CoreSetupCliConfigurationTemplate, CoreSetupProcessError> {
        if self.timeout_milliseconds == 0
            || self.timeout_milliseconds > 60_000
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > 1_048_576
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupCliConfigurationTemplate::new(
            normal_path(&self.entropy_source)?,
            normal_path(&self.launcher_file)?,
            self.privilege_command
                .as_deref()
                .map(normal_path)
                .transpose()?,
            self.timeout_milliseconds,
            self.maximum_response_bytes,
        ))
    }
}

// Stores the complete Node template whose listener and trust values are derived later.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeConfigurationDocument {
    core_update: NodeCoreUpdateConfigurationDocument,
    model: NodeModelConfigurationDocument,
    benchmark: Option<NodeBenchmarkConfigurationDocument>,
    hardware: HardwareDocument,
    pairing: PairingPlatformDocument,
    trust_workspace: String,
    daemon_cadence_milliseconds: u64,
    local_api: LocalApiDocument,
    placement_safety: NodePlacementSafetyDocument,
    remote_maximum_workers: usize,
    remote_accept_poll_interval_milliseconds: u64,
    remote_handshake_timeout_milliseconds: u64,
    remote_read_timeout_milliseconds: u64,
    remote_write_timeout_milliseconds: u64,
}

impl NodeConfigurationDocument {
    // Builds one platform-exact Node template after validating every path and positive bound.
    fn into_template(
        self,
        platform: CoreUpdateServicePlatform,
        openssl_command: PathBuf,
        trust_workspace_root: &Path,
    ) -> Result<CoreSetupNodeConfigurationTemplate, CoreSetupProcessError> {
        if self.hardware.platform() != platform
            || self.pairing.platform() != platform
            || self.placement_safety.platform() != platform
            || self.benchmark.is_some() != (platform == CoreUpdateServicePlatform::Linux)
            || !(MINIMUM_NODE_DAEMON_CADENCE_MILLISECONDS
                ..=MAXIMUM_NODE_DAEMON_CADENCE_MILLISECONDS)
                .contains(&self.daemon_cadence_milliseconds)
            || !(1..=MAXIMUM_NODE_WORKERS).contains(&self.remote_maximum_workers)
            || self.remote_accept_poll_interval_milliseconds == 0
            || self.remote_accept_poll_interval_milliseconds > MAXIMUM_ACCEPT_POLL_MILLISECONDS
            || [
                self.remote_handshake_timeout_milliseconds,
                self.remote_read_timeout_milliseconds,
                self.remote_write_timeout_milliseconds,
            ]
            .iter()
            .any(|value| *value == 0 || *value > MAXIMUM_NODE_TIMEOUT_MILLISECONDS)
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let core_update = self.core_update.into_input(platform)?;
        let model = self.model.into_input(platform)?;
        let benchmark = self
            .benchmark
            .map(NodeBenchmarkConfigurationDocument::into_template)
            .transpose()?;
        if core_update.curl_command != model.curl_command {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let trust_workspace = normal_path(&self.trust_workspace)?;
        if trust_workspace != trust_workspace_root.join(PAIRING_TRUST_WORKSPACE_NAME) {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupNodeConfigurationTemplate::new(
            core_update,
            model,
            benchmark,
            self.hardware.into_input()?,
            self.pairing.into_input()?,
            openssl_command,
            trust_workspace,
            self.daemon_cadence_milliseconds,
            self.local_api.into_node_input()?,
            self.placement_safety.into_template()?,
            self.remote_maximum_workers,
            self.remote_accept_poll_interval_milliseconds,
            self.remote_handshake_timeout_milliseconds,
            self.remote_read_timeout_milliseconds,
            self.remote_write_timeout_milliseconds,
        ))
    }
}

// Stores Linux benchmark roots and deadlines while setup derives every trust identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeBenchmarkConfigurationDocument {
    worker_executable: String,
    github_cli_command: String,
    task_root: String,
    telemetry_root: String,
    evidence_root: String,
    signing_workspace_root: String,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
    watchdog_timeout_milliseconds: u64,
}

impl NodeBenchmarkConfigurationDocument {
    // Closes every benchmark path and deadline before material identities are projected.
    fn into_template(self) -> Result<CoreSetupNodeBenchmarkTemplate, CoreSetupProcessError> {
        if self.maximum_runtime_milliseconds == 0
            || self.maximum_runtime_milliseconds > 7 * 24 * 60 * 60 * 1_000
            || self.stop_grace_milliseconds == 0
            || self.stop_grace_milliseconds > 10 * 60 * 1_000
            || self.stop_grace_milliseconds > self.maximum_runtime_milliseconds
            || self.watchdog_timeout_milliseconds == 0
            || self.watchdog_timeout_milliseconds > 60_000
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupNodeBenchmarkTemplate::new(
            normal_path(&self.worker_executable)?,
            normal_path(&self.github_cli_command)?,
            normal_path(&self.task_root)?,
            normal_path(&self.telemetry_root)?,
            normal_path(&self.evidence_root)?,
            normal_path(&self.signing_workspace_root)?,
            self.maximum_runtime_milliseconds,
            self.stop_grace_milliseconds,
            self.watchdog_timeout_milliseconds,
        ))
    }
}

// Stores every explicit production Core-update authority supplied by the signed installer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCoreUpdateConfigurationDocument {
    release_platform: String,
    letsinfer_home: String,
    home_directory: String,
    setup_state_directory: String,
    configuration_root: String,
    curl_command: String,
    ssh_keygen_command: String,
    allowed_signers_file: String,
    supervisor_command: String,
    readiness_timeout_milliseconds: u64,
    readiness_poll_milliseconds: u64,
    stable_readiness_observations: u32,
}

impl NodeCoreUpdateConfigurationDocument {
    // Closes release platform, persistent trust, native commands, roots, and readiness bounds.
    fn into_input(
        self,
        platform: CoreUpdateServicePlatform,
    ) -> Result<CoreSetupNodeUpdateInput, CoreSetupProcessError> {
        let platform_matches = matches!(
            (platform, self.release_platform.as_str()),
            (
                CoreUpdateServicePlatform::Linux,
                "linux_arm64" | "linux_x86_64"
            ) | (CoreUpdateServicePlatform::Macos, "macos_arm64")
        );
        if !platform_matches
            || self.readiness_timeout_milliseconds == 0
            || self.readiness_timeout_milliseconds > 300_000
            || self.readiness_poll_milliseconds == 0
            || self.readiness_poll_milliseconds > self.readiness_timeout_milliseconds
            || self.stable_readiness_observations == 0
            || self.stable_readiness_observations > 100
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupNodeUpdateInput {
            release_platform: self.release_platform,
            letsinfer_home: normal_path(&self.letsinfer_home)?,
            home_directory: normal_path(&self.home_directory)?,
            setup_state_directory: normal_path(&self.setup_state_directory)?,
            configuration_root: normal_path(&self.configuration_root)?,
            curl_command: normal_path(&self.curl_command)?,
            ssh_keygen_command: normal_path(&self.ssh_keygen_command)?,
            allowed_signers_file: normal_path(&self.allowed_signers_file)?,
            supervisor_command: normal_path(&self.supervisor_command)?,
            readiness_timeout_milliseconds: self.readiness_timeout_milliseconds,
            readiness_poll_milliseconds: self.readiness_poll_milliseconds,
            stable_readiness_observations: self.stable_readiness_observations,
        })
    }
}

// Stores every explicit production ModelCoordinator path and bounded native input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeModelConfigurationDocument {
    catalog_source: String,
    catalog_cache_root: String,
    catalog_hydration_root: String,
    http_workspace_root: String,
    installation_root: String,
    runtime_cache_root: String,
    curl_command: String,
    docker_command: String,
    command_working_directory: String,
    placement_material_root: String,
    placement_secret_root: String,
    placement_tls_workspace_root: String,
    first_port: u16,
    port_count: u16,
    endpoint_timeout_milliseconds: u64,
    maximum_hardware_age_milliseconds: u64,
    group_id: u32,
    launch_agents_root: Option<String>,
    launchctl_command: Option<String>,
}

impl NodeModelConfigurationDocument {
    // Closes every path and enforces platform-exact optional native execution values.
    fn into_input(
        self,
        platform: CoreUpdateServicePlatform,
    ) -> Result<CoreSetupNodeModelInput, CoreSetupProcessError> {
        let macos = platform == CoreUpdateServicePlatform::Macos;
        if !runtime_catalog_source(&self.catalog_source)
            || self.first_port == 0
            || self.port_count == 0
            || self.endpoint_timeout_milliseconds == 0
            || self.endpoint_timeout_milliseconds > 30_000
            || self.maximum_hardware_age_milliseconds == 0
            || self.maximum_hardware_age_milliseconds > 86_400_000
            || self.group_id == 0
            || macos != self.launch_agents_root.is_some()
            || macos != self.launchctl_command.is_some()
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupNodeModelInput {
            catalog_source: self.catalog_source,
            catalog_cache_root: normal_path(&self.catalog_cache_root)?,
            catalog_hydration_root: normal_path(&self.catalog_hydration_root)?,
            http_workspace_root: normal_path(&self.http_workspace_root)?,
            installation_root: normal_path(&self.installation_root)?,
            runtime_cache_root: normal_path(&self.runtime_cache_root)?,
            curl_command: normal_path(&self.curl_command)?,
            docker_command: normal_path(&self.docker_command)?,
            command_working_directory: normal_path(&self.command_working_directory)?,
            placement_material_root: normal_path(&self.placement_material_root)?,
            placement_secret_root: normal_path(&self.placement_secret_root)?,
            placement_tls_workspace_root: normal_path(&self.placement_tls_workspace_root)?,
            first_port: self.first_port,
            port_count: self.port_count,
            endpoint_timeout_milliseconds: self.endpoint_timeout_milliseconds,
            maximum_hardware_age_milliseconds: self.maximum_hardware_age_milliseconds,
            group_id: self.group_id,
            launch_agents_root: self
                .launch_agents_root
                .as_deref()
                .map(normal_path)
                .transpose()?,
            launchctl_command: self
                .launchctl_command
                .as_deref()
                .map(normal_path)
                .transpose()?,
        })
    }
}

// Returns whether one credential-free HTTPS source names the signed runtime catalog document.
fn runtime_catalog_source(value: &str) -> bool {
    if value.len() > 2_048
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.contains('@')
        || value.contains('#')
        || !value.ends_with("/catalog.json")
    {
        return false;
    }
    value.strip_prefix("https://").is_some_and(|remainder| {
        let authority = remainder.split('/').next().unwrap_or_default();
        !authority.is_empty()
            && authority != "."
            && authority != ".."
            && !authority.starts_with(':')
    })
}

// Selects one explicit Linux peer-verified channel or the distinct macOS launchd contract.
#[derive(Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum NodePlacementSafetyDocument {
    Linux {
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
        gateway: NodeProtectionExecutableDocument,
        watchdog: NodeProtectionExecutableDocument,
        lease_milliseconds: u64,
    },
    Macos,
}

// Stores one immutable installed executable and role-specific protection principal.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeProtectionExecutableDocument {
    path: String,
    executable_sha256: String,
    principal_id: String,
}

impl NodePlacementSafetyDocument {
    // Returns the platform fixed by this closed safety variant.
    const fn platform(&self) -> CoreUpdateServicePlatform {
        match self {
            Self::Linux { .. } => CoreUpdateServicePlatform::Linux,
            Self::Macos => CoreUpdateServicePlatform::Macos,
        }
    }

    // Validates every Linux bound and preserves macOS as a separate launchd authority.
    fn into_template(self) -> Result<CoreSetupNodePlacementSafetyTemplate, CoreSetupProcessError> {
        match self {
            Self::Linux {
                maximum_workers,
                read_timeout_milliseconds,
                write_timeout_milliseconds,
                accept_poll_interval_milliseconds,
                gateway,
                watchdog,
                lease_milliseconds,
            } => {
                if !(1..=MAXIMUM_NODE_WORKERS).contains(&maximum_workers)
                    || [read_timeout_milliseconds, write_timeout_milliseconds]
                        .iter()
                        .any(|value| *value == 0 || *value > MAXIMUM_NODE_TIMEOUT_MILLISECONDS)
                    || accept_poll_interval_milliseconds == 0
                    || accept_poll_interval_milliseconds > MAXIMUM_ACCEPT_POLL_MILLISECONDS
                    || lease_milliseconds == 0
                    || lease_milliseconds > 60_000
                {
                    return Err(CoreSetupProcessError::InvalidInput);
                }
                Ok(CoreSetupNodePlacementSafetyTemplate::Linux {
                    maximum_workers,
                    read_timeout_milliseconds,
                    write_timeout_milliseconds,
                    accept_poll_interval_milliseconds,
                    gateway: gateway.into_input()?,
                    watchdog: watchdog.into_input()?,
                    lease_milliseconds,
                })
            }
            Self::Macos => Ok(CoreSetupNodePlacementSafetyTemplate::MacosLaunchd),
        }
    }
}

impl NodeProtectionExecutableDocument {
    // Parses one canonical installed executable identity and bounded principal.
    fn into_input(self) -> Result<CoreSetupNodeProtectionExecutableInput, CoreSetupProcessError> {
        Ok(CoreSetupNodeProtectionExecutableInput::new(
            normal_path(&self.path)?,
            digest(&self.executable_sha256)?,
            CredentialId::parse(&self.principal_id)
                .map_err(|_| CoreSetupProcessError::InvalidInput)?,
        ))
    }
}

// Stores one platform-closed hardware provider selection.
#[derive(Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum HardwareDocument {
    Linux {
        architecture: ArchitectureDocument,
        boot_id_file: String,
        cpu_information_file: String,
        memory_information_file: String,
        nvidia_smi_command: Option<String>,
        rdma_command: Option<String>,
    },
    Macos {
        sysctl_command: String,
        metal_probe_command: String,
    },
}

impl HardwareDocument {
    // Returns the native platform fixed by this closed hardware variant.
    const fn platform(&self) -> CoreUpdateServicePlatform {
        match self {
            Self::Linux { .. } => CoreUpdateServicePlatform::Linux,
            Self::Macos { .. } => CoreUpdateServicePlatform::Macos,
        }
    }

    // Parses every hardware path and projects the exact production provider variant.
    fn into_input(self) -> Result<CoreSetupNodeHardwareInput, CoreSetupProcessError> {
        match self {
            Self::Linux {
                architecture,
                boot_id_file,
                cpu_information_file,
                memory_information_file,
                nvidia_smi_command,
                rdma_command,
            } => Ok(CoreSetupNodeHardwareInput::Linux {
                architecture: architecture.value(),
                boot_id_file: normal_path(&boot_id_file)?,
                cpu_information_file: normal_path(&cpu_information_file)?,
                memory_information_file: normal_path(&memory_information_file)?,
                nvidia_smi_command: optional_path(nvidia_smi_command.as_deref())?,
                rdma_command: optional_path(rdma_command.as_deref())?,
            }),
            Self::Macos {
                sysctl_command,
                metal_probe_command,
            } => Ok(CoreSetupNodeHardwareInput::MacosArm64 {
                sysctl_command: normal_path(&sysctl_command)?,
                metal_probe_command: normal_path(&metal_probe_command)?,
            }),
        }
    }
}

// Selects one supported Linux CPU architecture.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ArchitectureDocument {
    Arm64,
    X86_64,
}

impl ArchitectureDocument {
    // Projects the wire architecture onto the closed Core value.
    const fn value(self) -> CpuArchitecture {
        match self {
            Self::Arm64 => CpuArchitecture::Arm64,
            Self::X86_64 => CpuArchitecture::X86_64,
        }
    }
}

// Stores one platform-closed pairing discovery and direct-link provider selection.
#[derive(Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum PairingPlatformDocument {
    Linux {
        discovery_command: String,
        direct_link_sys_class: String,
        direct_link_ip_command: String,
    },
    Macos {
        discovery_command: String,
    },
}

impl PairingPlatformDocument {
    // Returns the native platform fixed by this closed pairing variant.
    const fn platform(&self) -> CoreUpdateServicePlatform {
        match self {
            Self::Linux { .. } => CoreUpdateServicePlatform::Linux,
            Self::Macos { .. } => CoreUpdateServicePlatform::Macos,
        }
    }

    // Parses every pairing native path and projects the production variant.
    fn into_input(self) -> Result<CoreSetupNodePairingPlatformInput, CoreSetupProcessError> {
        match self {
            Self::Linux {
                discovery_command,
                direct_link_sys_class,
                direct_link_ip_command,
            } => Ok(CoreSetupNodePairingPlatformInput::Linux {
                discovery_command: normal_path(&discovery_command)?,
                direct_link_sys_class: normal_path(&direct_link_sys_class)?,
                direct_link_ip_command: normal_path(&direct_link_ip_command)?,
            }),
            Self::Macos { discovery_command } => Ok(CoreSetupNodePairingPlatformInput::Macos {
                discovery_command: normal_path(&discovery_command)?,
            }),
        }
    }
}

// Stores one bounded owner-local API template.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalApiDocument {
    socket_path: String,
    maximum_workers: usize,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    accept_poll_interval_milliseconds: u64,
}

impl LocalApiDocument {
    // Builds one local Node API template only within the exact listener implementation bounds.
    fn into_node_input(self) -> Result<CoreSetupNodeLocalApiInput, CoreSetupProcessError> {
        if !(1..=MAXIMUM_NODE_WORKERS).contains(&self.maximum_workers)
            || [
                self.read_timeout_milliseconds,
                self.write_timeout_milliseconds,
            ]
            .iter()
            .any(|value| *value == 0 || *value > MAXIMUM_NODE_TIMEOUT_MILLISECONDS)
            || self.accept_poll_interval_milliseconds == 0
            || self.accept_poll_interval_milliseconds > MAXIMUM_ACCEPT_POLL_MILLISECONDS
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupNodeLocalApiInput::new(
            normal_path(&self.socket_path)?,
            self.maximum_workers,
            self.read_timeout_milliseconds,
            self.write_timeout_milliseconds,
            self.accept_poll_interval_milliseconds,
        ))
    }
}

// Stores the complete Gateway native state and bounded policy template.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayConfigurationDocument {
    health: LocalApiDocument,
    node_protection: GatewayProtectionDocument,
    telemetry_file: String,
    telemetry_cadence_milliseconds: u64,
    maximum_queue_milliseconds: u64,
    public_maximum_connections: usize,
    private_maximum_connections: usize,
}

// Stores every explicit Gateway-to-Node polling and cache bound.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayProtectionDocument {
    socket_path: String,
    read_timeout_milliseconds: u64,
    write_timeout_milliseconds: u64,
    maximum_cache_milliseconds: u64,
    poll_interval_milliseconds: u64,
}

impl GatewayConfigurationDocument {
    // Builds one Gateway template after closing every timing and positive capacity bound.
    fn into_template(self) -> Result<CoreSetupGatewayConfigurationTemplate, CoreSetupProcessError> {
        if !(MINIMUM_GATEWAY_TELEMETRY_CADENCE_MILLISECONDS
            ..=MAXIMUM_GATEWAY_TELEMETRY_CADENCE_MILLISECONDS)
            .contains(&self.telemetry_cadence_milliseconds)
            || self.maximum_queue_milliseconds > MAXIMUM_GATEWAY_QUEUE_MILLISECONDS
            || !(1..=MAXIMUM_GATEWAY_CONNECTIONS).contains(&self.public_maximum_connections)
            || !(1..=MAXIMUM_GATEWAY_CONNECTIONS).contains(&self.private_maximum_connections)
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let health = self.health;
        if !(1..=MAXIMUM_GATEWAY_HEALTH_WORKERS).contains(&health.maximum_workers)
            || [
                health.read_timeout_milliseconds,
                health.write_timeout_milliseconds,
            ]
            .iter()
            .any(|value| *value == 0 || *value > MAXIMUM_GATEWAY_HEALTH_TIMEOUT_MILLISECONDS)
            || health.accept_poll_interval_milliseconds == 0
            || health.accept_poll_interval_milliseconds > MAXIMUM_ACCEPT_POLL_MILLISECONDS
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let node_protection = &self.node_protection;
        if [
            node_protection.read_timeout_milliseconds,
            node_protection.write_timeout_milliseconds,
        ]
        .into_iter()
        .any(|value| value == 0 || value > MAXIMUM_GATEWAY_HEALTH_TIMEOUT_MILLISECONDS)
            || node_protection.maximum_cache_milliseconds == 0
            || node_protection.maximum_cache_milliseconds > 60_000
            || node_protection.poll_interval_milliseconds == 0
            || node_protection
                .poll_interval_milliseconds
                .checked_mul(2)
                .is_none_or(|margin| margin >= node_protection.maximum_cache_milliseconds)
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupGatewayConfigurationTemplate::new(
            CoreSetupGatewayHealthInput::new(
                normal_path(&health.socket_path)?,
                health.maximum_workers,
                health.read_timeout_milliseconds,
                health.write_timeout_milliseconds,
                health.accept_poll_interval_milliseconds,
            ),
            CoreSetupGatewayProtectionInput::new(
                normal_path(&self.node_protection.socket_path)?,
                self.node_protection.read_timeout_milliseconds,
                self.node_protection.write_timeout_milliseconds,
                self.node_protection.maximum_cache_milliseconds,
                self.node_protection.poll_interval_milliseconds,
            ),
            normal_path(&self.telemetry_file)?,
            self.telemetry_cadence_milliseconds,
            self.maximum_queue_milliseconds,
            self.public_maximum_connections,
            self.private_maximum_connections,
        ))
    }
}

// Stores every Linux-only Watchdog path, cadence, capacity, and threshold.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchdogConfigurationDocument {
    data_directory: String,
    controller_snapshot_path: String,
    site_state_path: String,
    gateway_metrics_path: String,
    protection_root_path: String,
    runtime_installation_root: String,
    runtime_cache_root: String,
    flush_interval_milliseconds: u32,
    maximum_controllers: usize,
    thresholds: WatchdogThresholdsDocument,
}

impl WatchdogConfigurationDocument {
    // Builds one Linux Watchdog template after validating every path and safety threshold.
    fn into_template(
        self,
        material_root: &Path,
    ) -> Result<CoreSetupWatchdogConfigurationTemplate, CoreSetupProcessError> {
        if !(MINIMUM_WATCHDOG_FLUSH_MILLISECONDS..=MAXIMUM_WATCHDOG_FLUSH_MILLISECONDS)
            .contains(&self.flush_interval_milliseconds)
            || !(1..=MAXIMUM_WATCHDOG_CONTROLLERS).contains(&self.maximum_controllers)
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        let protection_root_path = normal_path(&self.protection_root_path)?;
        if protection_root_path
            != material_root
                .join("watchdog")
                .join(WATCHDOG_PROTECTION_ROOT_NAME)
        {
            return Err(CoreSetupProcessError::InvalidInput);
        }
        Ok(CoreSetupWatchdogConfigurationTemplate::new(
            normal_path(&self.data_directory)?,
            normal_path(&self.controller_snapshot_path)?,
            normal_path(&self.site_state_path)?,
            normal_path(&self.gateway_metrics_path)?,
            protection_root_path,
            normal_path(&self.runtime_installation_root)?,
            normal_path(&self.runtime_cache_root)?,
            self.flush_interval_milliseconds,
            self.maximum_controllers,
            self.thresholds.into_value()?,
        ))
    }
}

// Stores every closed Watchdog protection threshold without native defaults.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchdogThresholdsDocument {
    warning_available_bytes: u64,
    graceful_available_bytes: u64,
    emergency_available_bytes: u64,
    swap_stop_bytes: u64,
    psi_some_microseconds: u64,
    psi_full_microseconds: u64,
    state_failures: u32,
    containment_grace_milliseconds: u32,
}

impl WatchdogThresholdsDocument {
    // Builds the production threshold value through its complete semantic validator.
    fn into_value(self) -> Result<WatchdogSafetyThresholds, CoreSetupProcessError> {
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
        .map_err(|_| CoreSetupProcessError::InvalidInput)
    }
}

// Stores one platform-closed native machine identity and Watchdog health selection.
#[derive(Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum NativeDocument {
    Linux {
        openssl_command: String,
        machine_identity_file: String,
        watchdog_health: WatchdogHealthDocument,
    },
    Macos {
        openssl_command: String,
        machine_identity_command: String,
        command_timeout_milliseconds: u64,
        command_poll_interval_milliseconds: u64,
    },
}

// Carries the native platform and shared OpenSSL executable after one boundary validation.
struct ResolvedNative {
    platform: CoreSetupPlatformInput,
    openssl_command: PathBuf,
}

impl NativeDocument {
    // Returns the platform fixed by this native identity variant.
    const fn platform(&self) -> CoreUpdateServicePlatform {
        match self {
            Self::Linux { .. } => CoreUpdateServicePlatform::Linux,
            Self::Macos { .. } => CoreUpdateServicePlatform::Macos,
        }
    }

    // Builds the production native input and requires exact generated Watchdog health paths.
    fn into_platform(
        self,
        expected_watchdog: Option<&CoreSetupWatchdogHealthInput>,
    ) -> Result<ResolvedNative, CoreSetupProcessError> {
        match self {
            Self::Linux {
                openssl_command,
                machine_identity_file,
                watchdog_health,
            } => {
                let watchdog_health = watchdog_health.into_input()?;
                if Some(&watchdog_health) != expected_watchdog {
                    return Err(CoreSetupProcessError::InvalidInput);
                }
                let platform = CoreSetupPlatformInput::linux(
                    normal_path(&machine_identity_file)?,
                    watchdog_health,
                )
                .map_err(|_| CoreSetupProcessError::InvalidInput)?;
                Ok(ResolvedNative {
                    platform,
                    openssl_command: openssl_path(&openssl_command)?,
                })
            }
            Self::Macos {
                openssl_command,
                machine_identity_command,
                command_timeout_milliseconds,
                command_poll_interval_milliseconds,
            } => {
                if expected_watchdog.is_some() {
                    return Err(CoreSetupProcessError::InvalidInput);
                }
                let platform = CoreSetupPlatformInput::macos(
                    normal_path(&machine_identity_command)?,
                    Duration::from_millis(command_timeout_milliseconds),
                    Duration::from_millis(command_poll_interval_milliseconds),
                )
                .map_err(|_| CoreSetupProcessError::InvalidInput)?;
                Ok(ResolvedNative {
                    platform,
                    openssl_command: openssl_path(&openssl_command)?,
                })
            }
        }
    }
}

// Stores the exact Linux Watchdog health authority and controller file identities.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchdogHealthDocument {
    authority_certificate_file: String,
    controller_certificate_file: String,
    controller_private_key_file: String,
}

impl WatchdogHealthDocument {
    // Parses one Linux Watchdog health input without loading any credential bytes.
    fn into_input(self) -> Result<CoreSetupWatchdogHealthInput, CoreSetupProcessError> {
        CoreSetupWatchdogHealthInput::new(
            normal_path(&self.authority_certificate_file)?,
            normal_path(&self.controller_certificate_file)?,
            normal_path(&self.controller_private_key_file)?,
        )
        .map_err(|_| CoreSetupProcessError::InvalidInput)
    }
}

// Parses one canonical absolute UTF-8 path without traversal or redundant separators.
fn normal_path(value: &str) -> Result<PathBuf, CoreSetupProcessError> {
    let path = PathBuf::from(value);
    if value.len() < 2
        || value.len() > 4 * 1024
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.chars().any(char::is_control)
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(CoreSetupProcessError::InvalidInput);
    }
    Ok(path)
}

// Parses one optional canonical absolute path without discovering a fallback.
fn optional_path(value: Option<&str>) -> Result<Option<PathBuf>, CoreSetupProcessError> {
    value.map(normal_path).transpose()
}

// Parses the exact OpenSSL executable without allowing a differently named native tool.
fn openssl_path(value: &str) -> Result<PathBuf, CoreSetupProcessError> {
    let path = normal_path(value)?;
    if path.file_name().and_then(|name| name.to_str()) != Some("openssl") {
        return Err(CoreSetupProcessError::InvalidInput);
    }
    Ok(path)
}

// Parses one exact lowercase SHA-256 identity.
fn digest(value: &str) -> Result<Sha256Digest, CoreSetupProcessError> {
    Sha256Digest::parse(value).map_err(|_| CoreSetupProcessError::InvalidInput)
}

// Parses one canonical literal socket address and rejects noncanonical aliases.
fn socket_address(value: &str) -> Result<SocketAddr, CoreSetupProcessError> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| CoreSetupProcessError::InvalidInput)?;
    if address.to_string() != value {
        return Err(CoreSetupProcessError::InvalidInput);
    }
    Ok(address)
}

// Parses one optional canonical socket address without assigning a listener.
fn optional_socket_address(
    value: Option<&str>,
) -> Result<Option<SocketAddr>, CoreSetupProcessError> {
    value.map(socket_address).transpose()
}
