// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::Sha256Digest;

use crate::li_core_setup::{
    CoreSetupConfigurationProvider, CoreSetupInstalledConfigurations, CoreSetupPreparedIdentity,
    CoreSetupPreparedMaterial, CoreSetupProviderError, CoreSetupReceipt, CoreSetupRequest,
};
use crate::li_core_setup_configuration::{
    validate_configuration_material_projection, CoreSetupCliInput, CoreSetupConfigurationBinding,
    CoreSetupConfigurationInput, CoreSetupConfigurationInstaller, CoreSetupGatewayHealthInput,
    CoreSetupGatewayInput, CoreSetupGatewayListenerInput, CoreSetupGatewayPrivateListenerInput,
    CoreSetupGatewayProtectionInput, CoreSetupNodeBenchmarkInput, CoreSetupNodeHardwareInput,
    CoreSetupNodeInput, CoreSetupNodeLocalApiInput, CoreSetupNodePairingInput,
    CoreSetupNodePairingPlatformInput, CoreSetupNodePlacementSafetyInput,
    CoreSetupNodeProtectionExecutableInput, CoreSetupNodeRemoteApiInput, CoreSetupNodeUpdateInput,
    CoreSetupWatchdogInput, CoreSetupWatchdogPathsInput, CoreSetupWatchdogProtectionInput,
};

// Carries every explicit input needed by the owner-local native CLI document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupCliConfigurationTemplate {
    entropy_source: PathBuf,
    launcher_file: PathBuf,
    privilege_command: Option<PathBuf>,
    timeout_milliseconds: u64,
    maximum_response_bytes: usize,
}

impl CoreSetupCliConfigurationTemplate {
    // Creates one immutable client template without discovering platform defaults.
    pub const fn new(
        entropy_source: PathBuf,
        launcher_file: PathBuf,
        privilege_command: Option<PathBuf>,
        timeout_milliseconds: u64,
        maximum_response_bytes: usize,
    ) -> Self {
        Self {
            entropy_source,
            launcher_file,
            privilege_command,
            timeout_milliseconds,
            maximum_response_bytes,
        }
    }
}

// Fixes the only configuration directory and owner accepted by one production provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupConfigurationLocation {
    directory: PathBuf,
    owner_user_id: u32,
}

impl CoreSetupConfigurationLocation {
    // Creates one explicit location without discovering the current user or filesystem layout.
    pub fn new(directory: PathBuf, owner_user_id: u32) -> Result<Self, CoreSetupProviderError> {
        if !is_normal_absolute_path(&directory) || directory == Path::new("/") {
            return Err(configuration_provider_unchanged(
                "configuration location is invalid",
            ));
        }
        Ok(Self {
            directory,
            owner_user_id,
        })
    }

    // Returns the fixed private directory used for installation and rollback.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    // Returns the fixed native owner used for every file observation and mutation.
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }
}

// Constructs complete typed resident input without performing configuration mutation.
pub trait CoreSetupConfigurationInputProvider: Send + Sync {
    // Returns the immutable implementation identity persisted against replay and rollback.
    fn provider_identity(&self) -> &Sha256Digest;

    // Resolves every native input from the exact setup, identity, and material closures.
    fn input(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupConfigurationInput, CoreSetupProviderError>;
}

// Carries every host-native Node path and timing that setup must receive explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeConfigurationTemplate {
    core_update: CoreSetupNodeUpdateInput,
    model: crate::CoreSetupNodeModelInput,
    benchmark: Option<CoreSetupNodeBenchmarkTemplate>,
    hardware: CoreSetupNodeHardwareInput,
    pairing_platform: CoreSetupNodePairingPlatformInput,
    openssl_command: PathBuf,
    trust_workspace: PathBuf,
    daemon_cadence_milliseconds: u64,
    local_api: CoreSetupNodeLocalApiInput,
    placement_safety: CoreSetupNodePlacementSafetyTemplate,
    remote_maximum_workers: usize,
    remote_accept_poll_interval_milliseconds: u64,
    remote_handshake_timeout_milliseconds: u64,
    remote_read_timeout_milliseconds: u64,
    remote_write_timeout_milliseconds: u64,
}

impl CoreSetupNodeConfigurationTemplate {
    // Creates one complete Node template without discovering commands, paths, ports, or timings.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        core_update: CoreSetupNodeUpdateInput,
        model: crate::CoreSetupNodeModelInput,
        benchmark: Option<CoreSetupNodeBenchmarkTemplate>,
        hardware: CoreSetupNodeHardwareInput,
        pairing_platform: CoreSetupNodePairingPlatformInput,
        openssl_command: PathBuf,
        trust_workspace: PathBuf,
        daemon_cadence_milliseconds: u64,
        local_api: CoreSetupNodeLocalApiInput,
        placement_safety: CoreSetupNodePlacementSafetyTemplate,
        remote_maximum_workers: usize,
        remote_accept_poll_interval_milliseconds: u64,
        remote_handshake_timeout_milliseconds: u64,
        remote_read_timeout_milliseconds: u64,
        remote_write_timeout_milliseconds: u64,
    ) -> Self {
        Self {
            core_update,
            model,
            benchmark,
            hardware,
            pairing_platform,
            openssl_command,
            trust_workspace,
            daemon_cadence_milliseconds,
            local_api,
            placement_safety,
            remote_maximum_workers,
            remote_accept_poll_interval_milliseconds,
            remote_handshake_timeout_milliseconds,
            remote_read_timeout_milliseconds,
            remote_write_timeout_milliseconds,
        }
    }

    // Returns every owner-private mutable root setup must create before Node starts.
    pub(crate) fn private_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![
            self.model.catalog_cache_root.clone(),
            self.model.catalog_hydration_root.clone(),
            self.model.http_workspace_root.clone(),
            self.model.installation_root.clone(),
            self.model.runtime_cache_root.clone(),
            self.model.command_working_directory.clone(),
            self.model.placement_material_root.clone(),
            self.model.placement_secret_root.clone(),
            self.model.placement_tls_workspace_root.clone(),
        ];
        if let Some(benchmark) = self.benchmark.as_ref() {
            roots.extend(benchmark.private_roots());
        }
        roots
    }

    // Returns the immutable runtime installation root shared with the Linux Watchdog.
    pub(crate) fn runtime_installation_root(&self) -> &Path {
        &self.model.installation_root
    }

    // Returns the mutable runtime cache root shared with placement and the Linux Watchdog.
    pub(crate) fn runtime_cache_root(&self) -> &Path {
        &self.model.runtime_cache_root
    }
}

// Carries Linux benchmark filesystem and deadline policy while setup supplies trust identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupNodeBenchmarkTemplate {
    worker_executable: PathBuf,
    github_cli_command: PathBuf,
    task_root: PathBuf,
    telemetry_root: PathBuf,
    evidence_root: PathBuf,
    signing_workspace_root: PathBuf,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
    watchdog_timeout_milliseconds: u64,
}

impl CoreSetupNodeBenchmarkTemplate {
    // Creates one explicit Linux benchmark template without discovering release or trust paths.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        worker_executable: PathBuf,
        github_cli_command: PathBuf,
        task_root: PathBuf,
        telemetry_root: PathBuf,
        evidence_root: PathBuf,
        signing_workspace_root: PathBuf,
        maximum_runtime_milliseconds: u64,
        stop_grace_milliseconds: u64,
        watchdog_timeout_milliseconds: u64,
    ) -> Self {
        Self {
            worker_executable,
            github_cli_command,
            task_root,
            telemetry_root,
            evidence_root,
            signing_workspace_root,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
            watchdog_timeout_milliseconds,
        }
    }

    // Returns every mutable benchmark root without exposing immutable executable or trust inputs.
    fn private_roots(&self) -> Vec<PathBuf> {
        vec![
            self.task_root.join("community_authority"),
            self.task_root.join("verifier_artifacts"),
            self.telemetry_root.clone(),
            self.evidence_root.clone(),
            self.signing_workspace_root.clone(),
        ]
    }
}

// Carries platform-native Node safety values while setup supplies shared dynamic identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreSetupNodePlacementSafetyTemplate {
    Linux {
        maximum_workers: usize,
        read_timeout_milliseconds: u64,
        write_timeout_milliseconds: u64,
        accept_poll_interval_milliseconds: u64,
        gateway: CoreSetupNodeProtectionExecutableInput,
        watchdog: CoreSetupNodeProtectionExecutableInput,
        lease_milliseconds: u64,
    },
    MacosLaunchd,
}

// Carries every host-native Gateway path, listener bound, and cadence except request addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupGatewayConfigurationTemplate {
    health: CoreSetupGatewayHealthInput,
    node_protection: CoreSetupGatewayProtectionInput,
    telemetry_file: PathBuf,
    telemetry_cadence_milliseconds: u64,
    maximum_queue_milliseconds: u64,
    public_maximum_connections: usize,
    private_maximum_connections: usize,
}

impl CoreSetupGatewayConfigurationTemplate {
    // Creates one complete Gateway template without discovering state paths or listener policy.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        health: CoreSetupGatewayHealthInput,
        node_protection: CoreSetupGatewayProtectionInput,
        telemetry_file: PathBuf,
        telemetry_cadence_milliseconds: u64,
        maximum_queue_milliseconds: u64,
        public_maximum_connections: usize,
        private_maximum_connections: usize,
    ) -> Self {
        Self {
            health,
            node_protection,
            telemetry_file,
            telemetry_cadence_milliseconds,
            maximum_queue_milliseconds,
            public_maximum_connections,
            private_maximum_connections,
        }
    }

    // Returns the exact private parent setup must own before Gateway publishes telemetry.
    pub(crate) fn telemetry_directory(&self) -> PathBuf {
        self.telemetry_file
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf()
    }

    // Returns the exact telemetry file shared with the Linux Watchdog observer.
    pub(crate) fn telemetry_file(&self) -> &Path {
        &self.telemetry_file
    }
}

// Carries Linux-only Watchdog state paths, cadence, controller bound, and thresholds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSetupWatchdogConfigurationTemplate {
    data_directory: PathBuf,
    controller_snapshot_path: PathBuf,
    site_state_path: PathBuf,
    gateway_metrics_path: PathBuf,
    protection_root_path: PathBuf,
    runtime_installation_root: PathBuf,
    runtime_cache_root: PathBuf,
    flush_interval_milliseconds: u32,
    maximum_controllers: usize,
    thresholds: li_watchdog_manager::WatchdogSafetyThresholds,
}

impl CoreSetupWatchdogConfigurationTemplate {
    // Creates one complete Linux Watchdog template without filesystem or network discovery.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        data_directory: PathBuf,
        controller_snapshot_path: PathBuf,
        site_state_path: PathBuf,
        gateway_metrics_path: PathBuf,
        protection_root_path: PathBuf,
        runtime_installation_root: PathBuf,
        runtime_cache_root: PathBuf,
        flush_interval_milliseconds: u32,
        maximum_controllers: usize,
        thresholds: li_watchdog_manager::WatchdogSafetyThresholds,
    ) -> Self {
        Self {
            data_directory,
            controller_snapshot_path,
            site_state_path,
            gateway_metrics_path,
            protection_root_path,
            runtime_installation_root,
            runtime_cache_root,
            flush_interval_milliseconds,
            maximum_controllers,
            thresholds,
        }
    }

    // Returns the exact Gateway telemetry file observed by the Watchdog.
    pub(crate) fn gateway_metrics_path(&self) -> &Path {
        &self.gateway_metrics_path
    }

    // Returns the Watchdog state directory that directly owns placement protection.
    pub(crate) fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    // Returns the private placement-protection root setup must own before Node starts.
    pub(crate) fn protection_root_path(&self) -> &Path {
        &self.protection_root_path
    }

    // Returns the immutable runtime installation root observed by the Watchdog.
    pub(crate) fn runtime_installation_root(&self) -> &Path {
        &self.runtime_installation_root
    }

    // Returns the mutable runtime cache root observed by the Watchdog.
    pub(crate) fn runtime_cache_root(&self) -> &Path {
        &self.runtime_cache_root
    }
}

// Builds production resident inputs from exact prepared identity/material and explicit host templates.
pub struct ApplicationCoreSetupConfigurationInputProvider {
    provider_identity: Sha256Digest,
    location: CoreSetupConfigurationLocation,
    cli: CoreSetupCliConfigurationTemplate,
    node: CoreSetupNodeConfigurationTemplate,
    gateway: CoreSetupGatewayConfigurationTemplate,
    watchdog: Option<CoreSetupWatchdogConfigurationTemplate>,
}

impl ApplicationCoreSetupConfigurationInputProvider {
    // Creates one concrete input builder whose native inputs remain immutable for its lifetime.
    pub const fn new(
        provider_identity: Sha256Digest,
        location: CoreSetupConfigurationLocation,
        cli: CoreSetupCliConfigurationTemplate,
        node: CoreSetupNodeConfigurationTemplate,
        gateway: CoreSetupGatewayConfigurationTemplate,
        watchdog: Option<CoreSetupWatchdogConfigurationTemplate>,
    ) -> Self {
        Self {
            provider_identity,
            location,
            cli,
            node,
            gateway,
            watchdog,
        }
    }
}

impl CoreSetupConfigurationInputProvider for ApplicationCoreSetupConfigurationInputProvider {
    // Returns the exact concrete-builder identity bound into durable configuration intent.
    fn provider_identity(&self) -> &Sha256Digest {
        &self.provider_identity
    }

    // Derives resident identities, addresses, and credential roles from prepared typed closures.
    fn input(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupConfigurationInput, CoreSetupProviderError> {
        let platform_matches = matches!(
            (
                request.context().platform(),
                &self.node.hardware,
                &self.node.pairing_platform,
            ),
            (
                li_core_update_manager::CoreUpdateServicePlatform::Linux,
                CoreSetupNodeHardwareInput::Linux { .. },
                CoreSetupNodePairingPlatformInput::Linux { .. },
            ) | (
                li_core_update_manager::CoreUpdateServicePlatform::Macos,
                CoreSetupNodeHardwareInput::MacosArm64 { .. },
                CoreSetupNodePairingPlatformInput::Macos { .. },
            )
        );
        let public_listener_matches = match request.context().role() {
            li_core_update_manager::CoreUpdateNodeRole::Main => {
                request.network().gateway_public_address().is_some()
            }
            li_core_update_manager::CoreUpdateNodeRole::Child => {
                request.network().gateway_public_address().is_none()
            }
        };
        if !platform_matches || !public_listener_matches {
            return Err(configuration_provider_unchanged(
                "configuration template does not match the setup platform or role",
            ));
        }
        let network = request.network();
        let pairing = material.pairing_trust();
        let node_trust = material.node_trust();
        let gateway_trust = material.gateway_trust();
        let placement_safety = match (
            request.context().platform(),
            &self.node.placement_safety,
            &self.watchdog,
        ) {
            (
                li_core_update_manager::CoreUpdateServicePlatform::Linux,
                CoreSetupNodePlacementSafetyTemplate::Linux {
                    maximum_workers,
                    read_timeout_milliseconds,
                    write_timeout_milliseconds,
                    accept_poll_interval_milliseconds,
                    gateway,
                    watchdog,
                    lease_milliseconds,
                },
                Some(watchdog_template),
            ) => CoreSetupNodePlacementSafetyInput::Linux {
                socket_path: self.gateway.node_protection.socket_path().to_path_buf(),
                maximum_workers: *maximum_workers,
                read_timeout_milliseconds: *read_timeout_milliseconds,
                write_timeout_milliseconds: *write_timeout_milliseconds,
                accept_poll_interval_milliseconds: *accept_poll_interval_milliseconds,
                protection_root: watchdog_template.protection_root_path.clone(),
                watchdog_source_identity: request.installation().source_identity().clone(),
                gateway: gateway.clone(),
                watchdog: watchdog.clone(),
                lease_milliseconds: *lease_milliseconds,
            },
            (
                li_core_update_manager::CoreUpdateServicePlatform::Macos,
                CoreSetupNodePlacementSafetyTemplate::MacosLaunchd,
                None,
            ) => CoreSetupNodePlacementSafetyInput::MacosLaunchd,
            _ => {
                return Err(configuration_provider_unchanged(
                    "Node placement-safety template does not match the platform",
                ))
            }
        };
        let node = CoreSetupNodeInput::new(
            material.database_file().to_path_buf(),
            self.node.core_update.clone(),
            self.node.model.clone(),
            self.benchmark_input(request, identity, material)?,
            material.pairing_setup_secret_file().to_path_buf(),
            CoreSetupNodePairingInput::new(
                self.node.pairing_platform.clone(),
                self.node.openssl_command.clone(),
                self.node.trust_workspace.clone(),
                pairing.site_private_key_file().to_path_buf(),
                pairing.site_public_key_file().to_path_buf(),
                pairing.site_ca_certificate_file().to_path_buf(),
                pairing.local_control_certificate_file().to_path_buf(),
                pairing.public_key_sha256().clone(),
                pairing.certificate_sha256().clone(),
            ),
            self.node.hardware.clone(),
            placement_safety,
            self.node.daemon_cadence_milliseconds,
            self.node.local_api.clone(),
            CoreSetupNodeRemoteApiInput::new(
                network.node_private_address(),
                self.node.remote_maximum_workers,
                self.node.remote_accept_poll_interval_milliseconds,
                self.node.remote_handshake_timeout_milliseconds,
                self.node.remote_read_timeout_milliseconds,
                self.node.remote_write_timeout_milliseconds,
                node_trust.server_certificate_file().to_path_buf(),
                node_trust.server_private_key_file().to_path_buf(),
                node_trust.authority_certificate_file().to_path_buf(),
            ),
        );
        let public_listener = network.gateway_public_address().map(|address| {
            CoreSetupGatewayListenerInput::new(address, self.gateway.public_maximum_connections)
        });
        let gateway = CoreSetupGatewayInput::new(
            identity.node_id().clone(),
            request.installation().version().clone(),
            request.installation().source_identity().clone(),
            self.gateway.health.clone(),
            self.gateway.node_protection.clone(),
            self.node.local_api.socket_path().to_path_buf(),
            self.gateway.telemetry_file.clone(),
            self.gateway.telemetry_cadence_milliseconds,
            self.gateway.maximum_queue_milliseconds,
            public_listener,
            CoreSetupGatewayPrivateListenerInput::new(
                CoreSetupGatewayListenerInput::new(
                    network.gateway_private_address(),
                    self.gateway.private_maximum_connections,
                ),
                gateway_trust.server_certificate_file().to_path_buf(),
                gateway_trust.server_private_key_file().to_path_buf(),
                gateway_trust.authority_certificate_file().to_path_buf(),
                gateway_trust.relay_client_certificate_file().to_path_buf(),
            ),
        );
        let watchdog = self.watchdog_input(request, identity, material)?;
        Ok(CoreSetupConfigurationInput::new(
            request.context(),
            self.location.directory().to_path_buf(),
            self.location.owner_user_id(),
            CoreSetupCliInput::new(
                self.node.local_api.socket_path().to_path_buf(),
                self.cli.entropy_source.clone(),
                self.cli.launcher_file.clone(),
                self.cli.privilege_command.clone(),
                self.cli.timeout_milliseconds,
                self.cli.maximum_response_bytes,
            ),
            node,
            gateway,
            watchdog,
        ))
    }
}

impl ApplicationCoreSetupConfigurationInputProvider {
    // Resolves the Linux-only benchmark contract from explicit templates and prepared trust.
    fn benchmark_input(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<Option<CoreSetupNodeBenchmarkInput>, CoreSetupProviderError> {
        match (
            request.context().platform(),
            request.network().watchdog_address(),
            &self.node.benchmark,
            &self.watchdog,
            material.benchmark_signing(),
            material.watchdog_trust(),
        ) {
            (
                li_core_update_manager::CoreUpdateServicePlatform::Linux,
                Some(address),
                Some(template),
                Some(watchdog_configuration),
                Some(signing),
                Some(watchdog),
            ) if address.ip().is_loopback() => Ok(Some(CoreSetupNodeBenchmarkInput::new(
                template.worker_executable.clone(),
                template.github_cli_command.clone(),
                template.task_root.clone(),
                template.telemetry_root.clone(),
                template.evidence_root.clone(),
                template.signing_workspace_root.clone(),
                signing.private_key_file().to_path_buf(),
                signing.public_key_file().to_path_buf(),
                template.maximum_runtime_milliseconds,
                template.stop_grace_milliseconds,
                address.ip().to_string(),
                address.port(),
                identity.control_address().as_str().to_owned(),
                watchdog.authority_certificate_file().to_path_buf(),
                watchdog.authority_private_key_file().to_path_buf(),
                watchdog.controller_allowlist_file().to_path_buf(),
                watchdog_configuration.controller_snapshot_path.clone(),
                watchdog.server_certificate_file().to_path_buf(),
                watchdog.server_private_key_file().to_path_buf(),
                watchdog.controller_certificate_file().to_path_buf(),
                watchdog.controller_private_key_file().to_path_buf(),
                template.watchdog_timeout_milliseconds,
            ))),
            (
                li_core_update_manager::CoreUpdateServicePlatform::Macos,
                None,
                None,
                None,
                Some(_),
                None,
            ) => Ok(None),
            _ => Err(configuration_provider_unchanged(
                "benchmark template, network, and material do not match the platform",
            )),
        }
    }

    // Resolves the exact Linux-only Watchdog projection and rejects platform-template mismatch.
    fn watchdog_input(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<Option<CoreSetupWatchdogInput>, CoreSetupProviderError> {
        match (
            request.context().platform(),
            request.network().watchdog_address(),
            &self.watchdog,
            material.watchdog_trust(),
        ) {
            (
                li_core_update_manager::CoreUpdateServicePlatform::Linux,
                Some(address),
                Some(template),
                Some(trust),
            ) => Ok(Some(CoreSetupWatchdogInput::new(
                identity.installation_id().clone(),
                identity.node_id().clone(),
                request.installation().version().clone(),
                request.installation().source_identity().clone(),
                address.ip(),
                address.port(),
                CoreSetupWatchdogPathsInput::new(
                    template.data_directory.clone(),
                    trust.server_certificate_file().to_path_buf(),
                    trust.server_private_key_file().to_path_buf(),
                    trust.authority_certificate_file().to_path_buf(),
                    trust.controller_allowlist_file().to_path_buf(),
                    template.controller_snapshot_path.clone(),
                    template.site_state_path.clone(),
                    template.gateway_metrics_path.clone(),
                    template.protection_root_path.clone(),
                    material.database_file().to_path_buf(),
                    template.runtime_installation_root.clone(),
                    template.runtime_cache_root.clone(),
                ),
                CoreSetupWatchdogProtectionInput::new(
                    self.gateway.node_protection.socket_path().to_path_buf(),
                    self.gateway.node_protection.read_timeout_milliseconds(),
                    self.gateway.node_protection.write_timeout_milliseconds(),
                ),
                template.flush_interval_milliseconds,
                template.maximum_controllers,
                template.thresholds,
            ))),
            (li_core_update_manager::CoreUpdateServicePlatform::Macos, None, None, None) => {
                Ok(None)
            }
            _ => Err(configuration_provider_unchanged(
                "Watchdog template, network, and material do not match the platform",
            )),
        }
    }
}

// Adapts the complete durable file transaction to CoreSetup's reversible phase contract.
pub struct ApplicationCoreSetupConfigurationProvider {
    location: CoreSetupConfigurationLocation,
    inputs: Arc<dyn CoreSetupConfigurationInputProvider>,
    installer: CoreSetupConfigurationInstaller,
}

impl ApplicationCoreSetupConfigurationProvider {
    // Creates one production adapter backed by descriptor-safe native configuration I/O.
    pub fn new(
        location: CoreSetupConfigurationLocation,
        inputs: Arc<dyn CoreSetupConfigurationInputProvider>,
    ) -> Self {
        Self {
            location,
            inputs,
            installer: CoreSetupConfigurationInstaller::new(),
        }
    }

    // Creates one adapter with an injected transaction owner for deterministic failure tests.
    pub fn with_installer(
        location: CoreSetupConfigurationLocation,
        inputs: Arc<dyn CoreSetupConfigurationInputProvider>,
        installer: CoreSetupConfigurationInstaller,
    ) -> Self {
        Self {
            location,
            inputs,
            installer,
        }
    }
}

impl CoreSetupConfigurationProvider for ApplicationCoreSetupConfigurationProvider {
    // Installs only input whose exact private references are bound to prepared material.
    fn install(
        &self,
        request: &CoreSetupRequest,
        identity: &CoreSetupPreparedIdentity,
        material: &CoreSetupPreparedMaterial,
    ) -> Result<CoreSetupInstalledConfigurations, CoreSetupProviderError> {
        validate_identity_binding(request, identity)?;
        let input = self.inputs.input(request, identity, material)?;
        if input.context() != request.context()
            || input.configuration_directory() != self.location.directory()
            || input.owner_user_id() != self.location.owner_user_id()
        {
            return Err(configuration_provider_unchanged(
                "configuration input location or service context is divergent",
            ));
        }
        validate_configuration_material_projection(&input, material)
            .map_err(|error| configuration_provider_unchanged(error.reason()))?;
        let provisioned_files = exact_material_files(request, material)?;
        let binding = CoreSetupConfigurationBinding::new(
            request.request_id().clone(),
            identity.receipt().identity().clone(),
            material.receipt().identity().clone(),
            material.material_identity().clone(),
            self.inputs.provider_identity().clone(),
            provisioned_files,
        )
        .map_err(|error| configuration_provider_unchanged(error.reason()))?;
        let installation = self
            .installer
            .install(&input, &binding)
            .map_err(configuration_installation_error)?;
        Ok(CoreSetupInstalledConfigurations::new(
            CoreSetupReceipt::new(installation.receipt_identity().clone()),
        ))
    }

    // Rolls back only the exact receipt owned by this fixed provider and configuration location.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        self.installer
            .rollback(
                self.location.directory(),
                self.location.owner_user_id(),
                self.inputs.provider_identity(),
                receipt.identity(),
            )
            .map_err(|error| configuration_provider_recovery(error.reason()))
    }
}

// Requires the prepared public identity to remain an exact projection of the setup request.
fn validate_identity_binding(
    request: &CoreSetupRequest,
    identity: &CoreSetupPreparedIdentity,
) -> Result<(), CoreSetupProviderError> {
    let expected_role = match request.context().role() {
        li_core_update_manager::CoreUpdateNodeRole::Main => li_core_interface::NodeRole::Main,
        li_core_update_manager::CoreUpdateNodeRole::Child => li_core_interface::NodeRole::Child,
    };
    if identity.display_name() != request.display_name()
        || identity.role() != expected_role
        || identity.control_address() != request.control_address()
    {
        return Err(configuration_provider_unchanged(
            "prepared identity does not match the setup request",
        ));
    }
    Ok(())
}

// Projects the exact prepared-material file closure for the selected role and platform.
fn exact_material_files(
    request: &CoreSetupRequest,
    material: &CoreSetupPreparedMaterial,
) -> Result<BTreeSet<PathBuf>, CoreSetupProviderError> {
    let expects_api_key =
        request.context().role() == li_core_update_manager::CoreUpdateNodeRole::Main;
    if material.api_key_file().is_some() != expects_api_key {
        return Err(configuration_provider_unchanged(
            "prepared API-key material does not match the node role",
        ));
    }
    let expects_watchdog =
        request.context().platform() == li_core_update_manager::CoreUpdateServicePlatform::Linux;
    if material.watchdog_trust().is_some() != expects_watchdog {
        return Err(configuration_provider_unchanged(
            "prepared Watchdog material does not match the platform",
        ));
    }
    if material.benchmark_signing().is_none() {
        return Err(configuration_provider_unchanged(
            "prepared benchmark signing material is unavailable",
        ));
    }
    let pairing = material.pairing_trust();
    let node = material.node_trust();
    let gateway = material.gateway_trust();
    let mut files = BTreeSet::from([
        material.database_file().to_path_buf(),
        material.pairing_setup_secret_file().to_path_buf(),
        pairing.site_private_key_file().to_path_buf(),
        pairing.site_public_key_file().to_path_buf(),
        pairing.site_ca_certificate_file().to_path_buf(),
        pairing.local_control_certificate_file().to_path_buf(),
        node.authority_private_key_file().to_path_buf(),
        node.authority_certificate_file().to_path_buf(),
        node.server_certificate_file().to_path_buf(),
        node.server_private_key_file().to_path_buf(),
        node.client_certificate_file().to_path_buf(),
        node.client_private_key_file().to_path_buf(),
        gateway.authority_private_key_file().to_path_buf(),
        gateway.authority_certificate_file().to_path_buf(),
        gateway.server_certificate_file().to_path_buf(),
        gateway.server_private_key_file().to_path_buf(),
        gateway.relay_client_certificate_file().to_path_buf(),
        gateway.relay_client_private_key_file().to_path_buf(),
    ]);
    if let Some(api_key_file) = material.api_key_file() {
        files.insert(api_key_file.to_path_buf());
    }
    if let Some(watchdog) = material.watchdog_trust() {
        files.extend([
            watchdog.authority_private_key_file().to_path_buf(),
            watchdog.authority_certificate_file().to_path_buf(),
            watchdog.server_certificate_file().to_path_buf(),
            watchdog.server_private_key_file().to_path_buf(),
            watchdog.controller_certificate_file().to_path_buf(),
            watchdog.controller_private_key_file().to_path_buf(),
            watchdog.controller_allowlist_file().to_path_buf(),
        ]);
    }
    if let Some(signing) = material.benchmark_signing() {
        files.extend([
            signing.private_key_file().to_path_buf(),
            signing.public_key_file().to_path_buf(),
        ]);
    }
    Ok(files)
}

// Maps one low-level transaction outcome into the provider's stable failure classification.
fn configuration_installation_error(
    error: crate::li_core_setup_configuration::CoreSetupConfigurationError,
) -> CoreSetupProviderError {
    if error.requires_recovery() {
        configuration_provider_recovery(error.reason())
    } else {
        configuration_provider_unchanged(error.reason())
    }
}

// Returns whether one path is absolute and contains no traversal, prefix, or redundant component.
fn is_normal_absolute_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && text.starts_with('/')
        && text.len() > 1
        && !text.ends_with('/')
        && !text.contains("//")
        && !text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Creates one unchanged provider failure before any durable configuration ownership exists.
const fn configuration_provider_unchanged(reason: &'static str) -> CoreSetupProviderError {
    CoreSetupProviderError::unchanged("configurations", reason)
}

// Creates one recovery-required provider failure while preserving durable configuration state.
const fn configuration_provider_recovery(reason: &'static str) -> CoreSetupProviderError {
    CoreSetupProviderError::recovery_required("configurations", reason)
}
