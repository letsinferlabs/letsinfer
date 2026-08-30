// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateResidentService, CoreUpdateServiceContext,
    CoreUpdateServiceControl, CoreUpdateServiceMode, CoreUpdateServicePlatform,
    CoreUpdateServiceState,
};

use crate::{
    CoreProcessLayout, CoreProcessPlatform, CoreResidentProcess, CoreServiceDefinition,
    CoreServiceDefinitionProvider,
};

const MAXIMUM_NATIVE_READINESS_TIMEOUT: Duration = Duration::from_secs(90);

// Carries one raw definition, native-load, and activity observation for exact retirement replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreNativeServiceRetirementState {
    definition_identity: Option<Sha256Digest>,
    loaded: bool,
    active: bool,
}

impl CoreNativeServiceRetirementState {
    // Creates one closed native observation while rejecting impossible loaded or active absence.
    pub fn new(
        definition_identity: Option<Sha256Digest>,
        loaded: bool,
        active: bool,
    ) -> Result<Self, CoreUpdateError> {
        if (loaded || active) && definition_identity.is_none() || (active && !loaded) {
            return Err(CoreUpdateError::InvalidContract {
                reason: "native service retirement state is inconsistent",
            });
        }
        Ok(Self {
            definition_identity,
            loaded,
            active,
        })
    }

    // Returns the exact bytes identity observed at the definition path when present.
    pub const fn definition_identity(&self) -> Option<&Sha256Digest> {
        self.definition_identity.as_ref()
    }

    // Returns whether the native supervisor still reports this definition loaded or enabled.
    pub const fn is_loaded(&self) -> bool {
        self.loaded
    }

    // Returns whether the native supervisor still reports this resident active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    // Returns whether this is the exact initial active state bound during preflight.
    pub fn is_active_identity(&self, expected: &Sha256Digest) -> bool {
        self.definition_identity.as_ref() == Some(expected) && self.loaded && self.active
    }

    // Returns whether this is one exact reachable retirement replay projection.
    pub fn is_retirement_replay(&self, expected: &Sha256Digest) -> bool {
        (!self.active && self.definition_identity.as_ref() == Some(expected))
            || (!self.loaded && !self.active && self.definition_identity.is_none())
    }

    // Returns whether retirement may begin or resume from this exact planned identity.
    pub fn is_retirable(&self, expected: &Sha256Digest) -> bool {
        self.is_active_identity(expected) || self.is_retirement_replay(expected)
    }
}

// Isolates systemd or launchd observation and mutation from Core update policy.
pub trait CoreNativeServiceSupervisor: Send + Sync {
    // Observes one exact resident service and returns its loaded-definition identity and activity.
    fn observe(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError>;

    // Observes definition presence separately from native load state for retirement replay.
    fn retirement_state(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
    ) -> Result<CoreNativeServiceRetirementState, CoreUpdateError> {
        let state = self.observe(platform, process)?;
        CoreNativeServiceRetirementState::new(
            state.loaded_identity().cloned(),
            state.was_loaded(),
            state.was_active(),
        )
    }

    // Retires only an exact preflight-bound active, reachable partial, or absent service state.
    fn retire(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        expected_definition_identity: &Sha256Digest,
    ) -> Result<(), CoreUpdateError> {
        if !self
            .retirement_state(platform, process)?
            .is_retirable(expected_definition_identity)
        {
            return Err(CoreUpdateError::InvalidContract {
                reason: "native service retirement identity changed",
            });
        }
        self.restore(platform, process, None, false)
    }

    // Atomically installs one exact definition and preserves the requested activity.
    fn install(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError>;

    // Tests one exact expected definition and activity without mutating native state.
    fn is_ready(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<bool, CoreUpdateError>;

    // Tests readiness within one caller-owned absolute-deadline remainder.
    fn is_ready_with_timeout(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
        timeout: std::time::Duration,
    ) -> Result<bool, CoreUpdateError> {
        if timeout.is_zero() {
            return Err(CoreUpdateError::provider(
                "native service",
                "native service readiness deadline expired",
            ));
        }
        self.is_ready(platform, process, definition, active)
    }

    // Restores one exact prior definition or its exact prior absence and activity.
    fn restore(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<(), CoreUpdateError>;
}

// Composes stable process definitions with platform-native observation and mutation capabilities.
pub struct ApplicationCoreUpdateServiceControl {
    context: CoreUpdateServiceContext,
    platform: CoreProcessPlatform,
    versions_root: std::path::PathBuf,
    configuration_root: std::path::PathBuf,
    log_root: std::path::PathBuf,
    definitions: CoreServiceDefinitionProvider,
    supervisor: Arc<dyn CoreNativeServiceSupervisor>,
}

impl ApplicationCoreUpdateServiceControl {
    // Creates one service-control boundary from explicit immutable and mutable roots.
    pub fn new(
        context: CoreUpdateServiceContext,
        letsinfer_home: std::path::PathBuf,
        configuration_root: std::path::PathBuf,
        supervisor: Arc<dyn CoreNativeServiceSupervisor>,
    ) -> Result<Self, CoreUpdateError> {
        let platform = process_platform(context.platform());
        let versions_root = letsinfer_home.join("core").join("versions");
        let log_root = letsinfer_home.join("logs");
        let validation_installation = versions_root.join("0.0.0").join("0".repeat(64));
        CoreProcessLayout::new(
            platform,
            validation_installation,
            configuration_root.clone(),
            log_root.clone(),
        )
        .map_err(|_| service_control_error("service roots are unsafe"))?;
        Ok(Self {
            context,
            platform,
            versions_root,
            configuration_root,
            log_root,
            definitions: CoreServiceDefinitionProvider,
            supervisor,
        })
    }

    // Generates one exact candidate or restoration definition from immutable identity.
    fn definition(
        &self,
        service: CoreUpdateResidentService,
        installation: &CoreInstallation,
    ) -> Result<CoreServiceDefinition, CoreUpdateError> {
        let root = self
            .versions_root
            .join(installation.version().as_str())
            .join(installation.source_identity().as_str());
        let layout = CoreProcessLayout::new(
            self.platform,
            root,
            self.configuration_root.clone(),
            self.log_root.clone(),
        )
        .map_err(|_| service_control_error("service layout is unsafe"))?;
        let command = layout
            .command(resident_process(service))
            .map_err(|_| service_control_error("resident service is unavailable"))?;
        self.definitions
            .definition(self.platform, &command)
            .map_err(|_| service_control_error("service definition could not be generated"))
    }
}

impl CoreUpdateServiceControl for ApplicationCoreUpdateServiceControl {
    // Returns the immutable platform and node role supplied at composition.
    fn context(&self) -> Result<CoreUpdateServiceContext, CoreUpdateError> {
        Ok(self.context)
    }

    // Delegates exact native observation and rejects a mismatched service identity.
    fn observe_service(
        &self,
        service: CoreUpdateResidentService,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        let observed = self
            .supervisor
            .observe(self.platform, resident_process(service))?;
        if observed.service() != service {
            return Err(CoreUpdateError::InvalidContract {
                reason: "native supervisor returned the wrong resident service",
            });
        }
        Ok(observed)
    }

    // Installs one manager-selected content-addressed service definition.
    fn rebind_service(
        &self,
        service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        installation: &CoreInstallation,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        let definition = self.definition(service, installation)?;
        self.supervisor.install(&definition, active)
    }

    // Tests one exact expected definition or exact absence and requested activity.
    fn service_is_ready(
        &self,
        service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
    ) -> Result<bool, CoreUpdateError> {
        let definition = installation
            .map(|installation| self.definition(service, installation))
            .transpose()?;
        self.supervisor.is_ready(
            self.platform,
            resident_process(service),
            definition.as_ref(),
            active,
        )
    }

    // Passes the caller's remaining global update deadline into the native supervisor.
    fn service_is_ready_with_timeout(
        &self,
        service: CoreUpdateResidentService,
        _mode: CoreUpdateServiceMode,
        installation: Option<&CoreInstallation>,
        active: bool,
        timeout: Duration,
    ) -> Result<bool, CoreUpdateError> {
        if timeout.is_zero() {
            return Err(CoreUpdateError::provider(
                "native service control",
                "service readiness deadline expired",
            ));
        }
        let definition = installation
            .map(|installation| self.definition(service, installation))
            .transpose()?;
        self.supervisor.is_ready_with_timeout(
            self.platform,
            resident_process(service),
            definition.as_ref(),
            active,
            timeout.min(MAXIMUM_NATIVE_READINESS_TIMEOUT),
        )
    }

    // Reconstructs and restores the exact previous definition or exact prior absence.
    fn restore_service(
        &self,
        state: &CoreUpdateServiceState,
        installation: &CoreInstallation,
    ) -> Result<(), CoreUpdateError> {
        let definition = state
            .was_loaded()
            .then(|| self.definition(state.service(), installation))
            .transpose()?;
        if definition
            .as_ref()
            .is_some_and(|value| Some(value.sha256()) != state.loaded_identity())
        {
            return Err(CoreUpdateError::InvalidContract {
                reason: "prior service identity does not match its exact definition",
            });
        }
        self.supervisor.restore(
            self.platform,
            resident_process(state.service()),
            definition.as_ref(),
            state.was_active(),
        )
    }
}

// Maps the update platform identity to the stable process platform identity.
const fn process_platform(platform: CoreUpdateServicePlatform) -> CoreProcessPlatform {
    match platform {
        CoreUpdateServicePlatform::Linux => CoreProcessPlatform::Linux,
        CoreUpdateServicePlatform::Macos => CoreProcessPlatform::Macos,
    }
}

// Maps one update service identity to its resident process contract.
const fn resident_process(service: CoreUpdateResidentService) -> CoreResidentProcess {
    match service {
        CoreUpdateResidentService::Node => CoreResidentProcess::Node,
        CoreUpdateResidentService::Gateway => CoreResidentProcess::Gateway,
        CoreUpdateResidentService::Watchdog => CoreResidentProcess::Watchdog,
    }
}

// Creates one stable redacted native-service provider failure.
fn service_control_error(reason: &'static str) -> CoreUpdateError {
    CoreUpdateError::provider("native service control", reason)
}
