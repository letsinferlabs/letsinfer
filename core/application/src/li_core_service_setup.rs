// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use li_core_interface::{NodeId, NodeRole, Sha256Digest};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};

use crate::{
    CoreNativeServiceSupervisor, CoreProcessLayout, CoreProcessPlatform, CoreResidentProcess,
    CoreResidentProcessCommand, CoreServiceDefinition, CoreServiceDefinitionProvider,
};

const SERVICE_READINESS_DEADLINE_SECONDS: u64 = 90;
const SERVICE_READINESS_INTERVAL_MILLISECONDS: u64 = 250;
const SERVICE_READINESS_STABLE_OBSERVATIONS: usize = 5;

// Identifies one durable exact-state cutover snapshot owned by the native provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceCutoverReceipt {
    receipt_id: Sha256Digest,
}

impl CoreServiceCutoverReceipt {
    // Creates one opaque provider receipt after a durable native snapshot exists.
    pub const fn new(receipt_id: Sha256Digest) -> Self {
        Self { receipt_id }
    }

    // Returns the exact provider identity required for commit or restoration.
    pub const fn receipt_id(&self) -> &Sha256Digest {
        &self.receipt_id
    }
}

// Identifies whether setup owns mutation or only verifies a prior committed replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreServiceCutoverBegin {
    Prepared(CoreServiceCutoverReceipt),
    AlreadyCommitted(CoreServiceCutoverReceipt),
}

// Identifies whether one interrupted native restoration still owns recovery work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreServiceCutoverRecovery {
    None,
    Restoring,
    Restored,
}

impl CoreServiceCutoverBegin {
    // Returns the exact durable receipt shared by either setup path.
    pub const fn receipt(&self) -> &CoreServiceCutoverReceipt {
        match self {
            Self::Prepared(receipt) | Self::AlreadyCommitted(receipt) => receipt,
        }
    }
}

// Owns the durable native-service snapshot required by atomic setup activation.
pub trait CoreServiceCutoverProvider: Send + Sync {
    // Snapshots original native state durably before replacing service ownership.
    fn begin(
        &self,
        context: CoreUpdateServiceContext,
        installation: &CoreInstallation,
        definitions: &[CoreServiceDefinition],
    ) -> Result<CoreServiceCutoverBegin, CoreServiceSetupError>;

    // Commits one verified cutover and retires its durable restoration snapshot idempotently.
    fn commit(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError>;

    // Restores exact definitions/enablement and active versus safe non-running intent.
    fn restore(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError>;

    // Observes one interrupted restoration without changing native or durable state.
    fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError>;

    // Completes native restoration while retaining its durable restored checkpoint.
    fn resume_recovery(&self) -> Result<(), CoreServiceSetupError>;

    // Clears only one durably restored checkpoint after outer setup compensation completes.
    fn complete_recovery(&self) -> Result<(), CoreServiceSetupError>;
}

// Verifies every immutable and mutable resident prerequisite before cutover authority exists.
pub trait CoreServiceSetupPreflight: Send + Sync {
    // Proves the exact installation, configuration set, service root, and user supervisor domain.
    fn verify(
        &self,
        context: CoreUpdateServiceContext,
        installation: &CoreInstallation,
        commands: &[CoreResidentProcessCommand],
    ) -> Result<(), CoreServiceSetupError>;
}

// Represents one explicit role-health or memory-envelope observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreServiceSetupObservation {
    Ready,
    NotReady,
    Unsupported,
}

// Binds setup readiness to the exact local Node identity prepared before activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreServiceSetupNodeIdentity {
    node_id: NodeId,
    role: NodeRole,
}

impl CoreServiceSetupNodeIdentity {
    // Creates one immutable readiness identity from the already-validated setup result.
    pub const fn new(node_id: NodeId, role: NodeRole) -> Self {
        Self { node_id, role }
    }

    // Returns the exact local Node identity expected from the live private API.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the exact setup role expected from the live private API.
    pub const fn role(&self) -> NodeRole {
        self.role
    }
}

// Supplies concrete resident role health and native memory-envelope observations.
pub trait CoreServiceSetupHealthProvider: Send + Sync {
    // Observes semantic or transport health without treating unsupported checks as success.
    fn resident_health(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError>;

    // Adds an exact setup Node identity without changing role-only non-setup consumers.
    fn resident_health_with_identity(
        &self,
        context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        _identity: Option<&CoreServiceSetupNodeIdentity>,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        self.resident_health(context, process, timeout)
    }

    // Verifies the configured resident memory envelope where the platform exposes it.
    fn memory_envelope(
        &self,
        context: CoreUpdateServiceContext,
        definition: &CoreServiceDefinition,
        timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError>;
}

// Isolates monotonic setup time and bounded resident-readiness waits for deterministic tests.
pub trait CoreServiceSetupWaiter: Send + Sync {
    // Returns elapsed monotonic time from one stable process-local epoch.
    fn now(&self) -> Result<Duration, CoreServiceSetupError>;

    // Waits for one exact interval before the next readiness observation.
    fn wait(&self, duration: Duration) -> Result<(), CoreServiceSetupError>;
}

// Applies resident-readiness waits through the host monotonic sleep primitive.
#[derive(Clone, Debug)]
pub struct SystemCoreServiceSetupWaiter {
    epoch: Instant,
}

impl Default for SystemCoreServiceSetupWaiter {
    // Anchors one setup clock to an immutable monotonic process-local epoch.
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl CoreServiceSetupWaiter for SystemCoreServiceSetupWaiter {
    // Returns elapsed monotonic time without consulting the wall clock.
    fn now(&self) -> Result<Duration, CoreServiceSetupError> {
        Ok(self.epoch.elapsed())
    }

    // Sleeps only within the fixed nonzero setup polling interval.
    fn wait(&self, duration: Duration) -> Result<(), CoreServiceSetupError> {
        if duration.is_zero()
            || duration > Duration::from_millis(SERVICE_READINESS_INTERVAL_MILLISECONDS)
        {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "service readiness interval is invalid",
            });
        }
        std::thread::sleep(duration);
        Ok(())
    }
}

// Describes one stable first-setup service transaction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreServiceSetupError {
    InvalidContract {
        reason: &'static str,
    },
    Provider {
        capability: &'static str,
        reason: &'static str,
    },
    RolledBack {
        reason: &'static str,
    },
    RecoveryRequired {
        reason: &'static str,
    },
}

impl CoreServiceSetupError {
    // Creates one redacted provider failure without retaining a native path or command.
    pub const fn provider(capability: &'static str, reason: &'static str) -> Self {
        Self::Provider { capability, reason }
    }
}

impl fmt::Display for CoreServiceSetupError {
    // Presents stable service-setup language without native definition contents.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { reason } => {
                write!(
                    formatter,
                    "Core service setup contract is invalid: {reason}"
                )
            }
            Self::Provider { capability, reason } => {
                write!(
                    formatter,
                    "Core service setup {capability} failed: {reason}"
                )
            }
            Self::RolledBack { reason } => {
                write!(formatter, "Core service setup rolled back: {reason}")
            }
            Self::RecoveryRequired { reason } => {
                write!(formatter, "Core service setup requires recovery: {reason}")
            }
        }
    }
}

impl Error for CoreServiceSetupError {}

// Coordinates one first Rust service cutover without owning native persistence mechanics.
pub struct CoreServiceSetup {
    context: CoreUpdateServiceContext,
    platform: CoreProcessPlatform,
    versions_root: PathBuf,
    configuration_root: PathBuf,
    log_root: PathBuf,
    definitions: CoreServiceDefinitionProvider,
    supervisor: Arc<dyn CoreNativeServiceSupervisor>,
    cutover: Arc<dyn CoreServiceCutoverProvider>,
    preflight: Arc<dyn CoreServiceSetupPreflight>,
    health: Arc<dyn CoreServiceSetupHealthProvider>,
    waiter: Arc<dyn CoreServiceSetupWaiter>,
}

impl CoreServiceSetup {
    // Creates one setup boundary from exact platform roots and complete production capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: CoreUpdateServiceContext,
        letsinfer_home: PathBuf,
        configuration_root: PathBuf,
        supervisor: Arc<dyn CoreNativeServiceSupervisor>,
        cutover: Arc<dyn CoreServiceCutoverProvider>,
        preflight: Arc<dyn CoreServiceSetupPreflight>,
        health: Arc<dyn CoreServiceSetupHealthProvider>,
    ) -> Result<Self, CoreServiceSetupError> {
        Self::new_with_waiter(
            context,
            letsinfer_home,
            configuration_root,
            supervisor,
            cutover,
            preflight,
            health,
            Arc::new(SystemCoreServiceSetupWaiter::default()),
        )
    }

    // Creates one setup boundary with an explicit bounded readiness-wait capability.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_waiter(
        context: CoreUpdateServiceContext,
        letsinfer_home: PathBuf,
        configuration_root: PathBuf,
        supervisor: Arc<dyn CoreNativeServiceSupervisor>,
        cutover: Arc<dyn CoreServiceCutoverProvider>,
        preflight: Arc<dyn CoreServiceSetupPreflight>,
        health: Arc<dyn CoreServiceSetupHealthProvider>,
        waiter: Arc<dyn CoreServiceSetupWaiter>,
    ) -> Result<Self, CoreServiceSetupError> {
        let platform = process_platform(context.platform());
        let versions_root = letsinfer_home.join("core").join("versions");
        let log_root = letsinfer_home.join("logs");
        CoreProcessLayout::new(
            platform,
            versions_root.join("0.0.0").join("0".repeat(64)),
            configuration_root.clone(),
            log_root.clone(),
        )
        .map_err(|_| CoreServiceSetupError::InvalidContract {
            reason: "service roots are unsafe",
        })?;
        Ok(Self {
            context,
            platform,
            versions_root,
            configuration_root,
            log_root,
            definitions: CoreServiceDefinitionProvider,
            supervisor,
            cutover,
            preflight,
            health,
            waiter,
        })
    }

    // Generates the complete deterministic resident commands and definitions for one installation.
    fn service_contracts(
        &self,
        installation: &CoreInstallation,
    ) -> Result<(Vec<CoreResidentProcessCommand>, Vec<CoreServiceDefinition>), CoreServiceSetupError>
    {
        let installation_root = self
            .versions_root
            .join(installation.version().as_str())
            .join(installation.source_identity().as_str());
        let layout = CoreProcessLayout::new(
            self.platform,
            installation_root,
            self.configuration_root.clone(),
            self.log_root.clone(),
        )
        .map_err(|_| CoreServiceSetupError::InvalidContract {
            reason: "service layout is unsafe",
        })?;
        let commands = layout
            .commands()
            .map_err(|_| CoreServiceSetupError::InvalidContract {
                reason: "resident service set is unavailable",
            })?;
        let definitions = commands
            .iter()
            .map(|command| {
                self.definitions
                    .definition(self.platform, command)
                    .map_err(|_| CoreServiceSetupError::InvalidContract {
                        reason: "resident service definition is invalid",
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((commands, definitions))
    }

    // Restores the durable original snapshot and classifies incomplete compensation.
    fn rollback<Value>(
        &self,
        receipt: &CoreServiceCutoverReceipt,
        reason: &'static str,
    ) -> Result<Value, CoreServiceSetupError> {
        match self.cutover.restore(receipt) {
            Ok(()) => Err(CoreServiceSetupError::RolledBack { reason }),
            Err(_) => Err(CoreServiceSetupError::RecoveryRequired { reason }),
        }
    }

    // Observes one interrupted cutover before source-bound setup replay validation.
    pub fn recovery(&self) -> Result<CoreServiceCutoverRecovery, CoreServiceSetupError> {
        self.cutover.recovery()
    }

    // Restores one interrupted native cutover without prematurely clearing its checkpoint.
    pub fn resume_recovery(&self) -> Result<(), CoreServiceSetupError> {
        self.cutover.resume_recovery()
    }

    // Retires one restored checkpoint after every reversible setup phase is compensated.
    pub fn complete_recovery(&self) -> Result<(), CoreServiceSetupError> {
        self.cutover.complete_recovery()
    }

    // Requires the complete resident set to remain ready for five consecutive observations.
    fn await_readiness(
        &self,
        definitions: &[CoreServiceDefinition],
        identity: Option<&CoreServiceSetupNodeIdentity>,
    ) -> Result<bool, CoreServiceSetupError> {
        let started_at = self.waiter.now()?;
        let deadline = started_at
            .checked_add(Duration::from_secs(SERVICE_READINESS_DEADLINE_SECONDS))
            .ok_or(CoreServiceSetupError::InvalidContract {
                reason: "service readiness deadline is invalid",
            })?;
        let mut last_observed_at = started_at;
        let mut stable_observations = 0_usize;
        loop {
            let mut complete = true;
            for definition in definitions {
                let before = self.remaining_readiness(deadline, &mut last_observed_at)?;
                if before.is_zero() {
                    return Ok(false);
                }
                match self.supervisor.is_ready_with_timeout(
                    self.platform,
                    definition.process(),
                    Some(definition),
                    true,
                    before,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        complete = false;
                        break;
                    }
                    Err(_) => {
                        return Err(CoreServiceSetupError::provider(
                            "service readiness",
                            "a resident service could not be observed",
                        ));
                    }
                }
                let after_native = self.remaining_readiness(deadline, &mut last_observed_at)?;
                if after_native.is_zero() {
                    return Ok(false);
                }
                let health = self.health.resident_health_with_identity(
                    self.context,
                    definition.process(),
                    identity,
                    after_native,
                )?;
                let after_health = self.remaining_readiness(deadline, &mut last_observed_at)?;
                if after_health.is_zero() {
                    return Ok(false);
                }
                if !health_satisfies_contract(definition.process(), health)? {
                    complete = false;
                    break;
                }
                let memory = self
                    .health
                    .memory_envelope(self.context, definition, after_health)?;
                let after_memory = self.remaining_readiness(deadline, &mut last_observed_at)?;
                if after_memory.is_zero() {
                    return Ok(false);
                }
                if !memory_satisfies_contract(self.platform, memory)? {
                    complete = false;
                    break;
                }
            }
            if complete {
                stable_observations += 1;
                if stable_observations == SERVICE_READINESS_STABLE_OBSERVATIONS {
                    return Ok(true);
                }
            } else {
                stable_observations = 0;
            }
            let remaining = self.remaining_readiness(deadline, &mut last_observed_at)?;
            if remaining.is_zero() {
                return Ok(false);
            }
            self.waiter.wait(remaining.min(Duration::from_millis(
                SERVICE_READINESS_INTERVAL_MILLISECONDS,
            )))?;
        }
    }

    // Returns the exact remaining deadline while rejecting a regressed injected clock.
    fn remaining_readiness(
        &self,
        deadline: Duration,
        last_observed_at: &mut Duration,
    ) -> Result<Duration, CoreServiceSetupError> {
        let observed_at = self.waiter.now()?;
        if observed_at < *last_observed_at {
            return Err(CoreServiceSetupError::provider(
                "service readiness clock",
                "monotonic time regressed",
            ));
        }
        *last_observed_at = observed_at;
        Ok(deadline.saturating_sub(observed_at))
    }

    // Installs and verifies every resident before committing native-service activation.
    pub fn apply(
        &self,
        installation: &CoreInstallation,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError> {
        self.apply_with_identity(installation, None)
    }

    // Installs one setup-owned resident set bound to its exact prepared local Node identity.
    pub fn apply_for_node(
        &self,
        installation: &CoreInstallation,
        identity: &CoreServiceSetupNodeIdentity,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError> {
        self.apply_with_identity(installation, Some(identity))
    }

    // Applies one service transaction with optional setup-only Node identity binding.
    fn apply_with_identity(
        &self,
        installation: &CoreInstallation,
        identity: Option<&CoreServiceSetupNodeIdentity>,
    ) -> Result<CoreServiceCutoverReceipt, CoreServiceSetupError> {
        let (commands, definitions) = self.service_contracts(installation)?;
        self.preflight
            .verify(self.context, installation, &commands)?;
        let begin = self
            .cutover
            .begin(self.context, installation, &definitions)?;
        let receipt = match begin {
            CoreServiceCutoverBegin::Prepared(receipt) => receipt,
            CoreServiceCutoverBegin::AlreadyCommitted(receipt) => {
                return match self.await_readiness(&definitions, identity) {
                    Ok(true) => Ok(receipt),
                    Ok(false) | Err(_) => Err(CoreServiceSetupError::RecoveryRequired {
                        reason: "committed resident services did not verify ready",
                    }),
                }
            }
        };
        for definition in &definitions {
            if self.supervisor.install(definition, true).is_err() {
                return self.rollback(&receipt, "a resident service could not be installed");
            }
        }
        match self.await_readiness(&definitions, identity) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                return self.rollback(&receipt, "a resident service did not become ready");
            }
        }
        self.cutover.commit(&receipt)?;
        Ok(receipt)
    }

    // Returns the immutable platform/role context bound to this setup transaction.
    pub const fn context(&self) -> CoreUpdateServiceContext {
        self.context
    }
}

// Maps one update platform identity to its native process contract.
const fn process_platform(platform: CoreUpdateServicePlatform) -> CoreProcessPlatform {
    match platform {
        CoreUpdateServicePlatform::Linux => CoreProcessPlatform::Linux,
        CoreUpdateServicePlatform::Macos => CoreProcessPlatform::Macos,
    }
}

// Requires one concrete healthy observation for every resident role.
fn health_satisfies_contract(
    process: CoreResidentProcess,
    observation: CoreServiceSetupObservation,
) -> Result<bool, CoreServiceSetupError> {
    match (process, observation) {
        (_, CoreServiceSetupObservation::Ready) => Ok(true),
        (_, CoreServiceSetupObservation::NotReady) => Ok(false),
        (_, CoreServiceSetupObservation::Unsupported) => Err(CoreServiceSetupError::provider(
            "resident health",
            "a concrete resident health check is unavailable",
        )),
    }
}

// Requires Linux memory accounting while retaining explicit macOS unsupported state.
fn memory_satisfies_contract(
    platform: CoreProcessPlatform,
    observation: CoreServiceSetupObservation,
) -> Result<bool, CoreServiceSetupError> {
    match (platform, observation) {
        (_, CoreServiceSetupObservation::Ready) => Ok(true),
        (_, CoreServiceSetupObservation::NotReady) => Ok(false),
        (CoreProcessPlatform::Linux, CoreServiceSetupObservation::Unsupported) => {
            Err(CoreServiceSetupError::provider(
                "service memory envelope",
                "Linux memory accounting is unavailable",
            ))
        }
        (CoreProcessPlatform::Macos, CoreServiceSetupObservation::Unsupported) => Ok(true),
    }
}
