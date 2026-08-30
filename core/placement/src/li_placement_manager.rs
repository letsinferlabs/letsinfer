// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

mod li_linux_container_provider;
mod li_linux_placement_executor;
mod li_linux_protection_provider;
mod li_macos_placement_executor;
mod li_placement_allocator;
mod li_placement_benchmark_provider;
mod li_placement_benchmark_reset;
mod li_placement_contract;
mod li_placement_credentials;
mod li_placement_endpoint_readiness;
mod li_placement_lifecycle;
mod li_placement_log;
mod li_placement_material_provider;
mod li_runtime_execution_adapter;
mod li_runtime_launch_plan_resolver;
mod li_shell_free_command;

pub use li_linux_container_provider::{
    DockerContainerObservation, DockerLinuxPlacementExecutionProvider,
    DockerLinuxPlacementLogProvider, DockerLogRead, LinuxContainerLaunchPlan,
    LinuxContainerReadiness, LinuxDockerClient, LinuxDockerLogClient,
    LinuxEndpointReadinessProvider, LinuxPlacementMaterialProvider, LinuxPlacementWaiter,
    LinuxProcessIdentityIo, LinuxProcessIdentityProvider, PollingLinuxContainerReadinessProvider,
    ProcfsLinuxProcessIdentityProvider, SystemDockerClient, SystemLinuxPlacementWaiter,
    SystemLinuxProcessIdentityIo,
};
pub use li_linux_placement_executor::{
    LinuxPlacementExecutionObservation, LinuxPlacementExecutionProvider,
    LinuxPlacementExecutionState, LinuxPlacementExecutor, LinuxPlacementProtectedTargetProvider,
    LinuxPlacementProtectionProvider, LinuxProtectedProcessIdentity, PlacementProtectedTarget,
    PlacementProtectionGeneration, PlacementProtectionPhase, PlacementProtectionStatus,
};
pub use li_linux_protection_provider::{
    FilesystemLinuxPlacementProtectionProvider, LinuxProtectionIo,
    PlacementProtectionGenerationProvider, SystemLinuxProtectionIo,
    SystemProtectionGenerationProvider,
};
pub use li_macos_placement_executor::{
    macos_launch_agent_plist, FilesystemMacosPlacementLogProvider, MacosEndpointReadinessProvider,
    MacosLaunchAgentIo, MacosLaunchAgentPlan, MacosLaunchAgentService, MacosLaunchAgentStatus,
    MacosPlacementExecutor, MacosPlacementMaterialProvider, MacosPlacementWaiter,
    MacosPrivateLogRead, SystemMacosLaunchAgentIo, SystemMacosLaunchAgentService,
    SystemMacosPlacementWaiter,
};
use li_placement_allocator::allocate;
pub use li_placement_benchmark_provider::FilesystemPlacementBenchmarkResetProvider;
pub use li_placement_benchmark_reset::{
    LinuxPlacementBenchmarkProcessProvider, PlacementBenchmarkGenerations,
    PlacementBenchmarkIsolationReceipt, PlacementBenchmarkIsolationRequest,
    PlacementBenchmarkProcessProvider, PlacementBenchmarkResetProvider,
    PlacementBenchmarkResetReceipt, PlacementBenchmarkResetRequest,
    PlacementBenchmarkRestorationReceipt,
};
use li_placement_contract::placement_resources;
pub use li_placement_contract::{
    PlacementAdmissionPolicy, PlacementChange, PlacementClock, PlacementError, PlacementEvent,
    PlacementExecutor, PlacementIdentityProvider, PlacementLink, PlacementNodeResources,
    PlacementObservation, PlacementRecord, PlacementRequest, PlacementStore, PlacementTask,
    SystemPlacementClock, SystemPlacementIdentityProvider, VersionedPlacementRecord,
};
pub use li_placement_credentials::{
    FilesystemPlacementCredentialProvider, FilesystemPlacementCredentialReader,
    OpenSslPlacementTlsMaterialProvider, PlacementCredentialDisposition,
    PlacementCredentialProvider, PlacementCredentialProvision, PlacementCredentialReader,
    PlacementCredentialReferences, PlacementSecretIo, PlacementSecretMaterial,
    PlacementSecretMaterialProvider, PlacementTlsMaterial, PlacementTlsMaterialProvider,
    PlacementTlsWorkspaceIo, RandomPlacementSecretMaterialProvider, SystemPlacementSecretIo,
    SystemPlacementTlsWorkspaceIo,
};
pub use li_placement_endpoint_readiness::SystemPlacementEndpointReadinessProvider;
use li_placement_lifecycle::PlacementLifecycle;
pub use li_placement_log::{
    PlacementLogBatch, PlacementLogCursor, PlacementLogReadRequest, PlacementRuntimeLogProvider,
};
pub use li_placement_material_provider::{
    FilesystemPlacementMaterialProvider, FilesystemPlacementMaterialReader,
    PlacementLaunchPlanIdentityProvider, PlacementLaunchPlanResolver,
    PlacementMaterialIdentityProvider, PlacementMaterialIo, ResolvedPlacementLaunchPlan,
    StoredPlacementLaunchPlanIdentityProvider, SystemPlacementMaterialIdentityProvider,
    SystemPlacementMaterialIo,
};
pub use li_runtime_execution_adapter::{
    LinuxRuntimePlacementEnvironment, MacosRuntimeExecutableIdentityProvider,
    MacosRuntimePlacementEnvironment, RuntimeManagerPlacementExecutionAdapter,
    SystemMacosRuntimeExecutableIdentityProvider,
};
pub use li_runtime_launch_plan_resolver::{
    LinuxRuntimeLaunchTemplate, MacosRuntimeLaunchTemplate, RuntimePlacementExecution,
    RuntimePlacementExecutionProvider, RuntimePlacementLaunchPlanResolver,
    RuntimePlacementReadiness, RuntimeServingContract,
};
pub use li_shell_free_command::{
    ShellFreeCommand, ShellFreeCommandOutput, ShellFreeCommandRunner, ShellFreeEnvironmentValue,
    SystemShellFreeCommandRunner,
};

use li_core_interface::PlacementGroupId;

// Owns exact resource allocation and one complete atomic placement-group lifecycle.
pub struct PlacementManager {
    store: Arc<dyn PlacementStore>,
    lifecycle: PlacementLifecycle,
    clock: Arc<dyn PlacementClock>,
    logs: Option<Arc<dyn PlacementRuntimeLogProvider>>,
    benchmark_resets: Option<Arc<dyn PlacementBenchmarkResetProvider>>,
}

impl PlacementManager {
    // Creates one manager from explicit persistence, execution, identity, and clock capabilities.
    pub fn new(
        store: Arc<dyn PlacementStore>,
        executor: Arc<dyn PlacementExecutor>,
        identity: Arc<dyn PlacementIdentityProvider>,
        clock: Arc<dyn PlacementClock>,
        admission: PlacementAdmissionPolicy,
    ) -> Self {
        Self {
            store: store.clone(),
            lifecycle: PlacementLifecycle::new(store, executor, identity, clock.clone(), admission),
            clock,
            logs: None,
            benchmark_resets: None,
        }
    }

    // Adds one native bounded runtime-log reader without changing lifecycle ownership.
    pub fn with_log_provider(mut self, logs: Arc<dyn PlacementRuntimeLogProvider>) -> Self {
        self.logs = Some(logs);
        self
    }

    // Adds one durable platform-native benchmark reset provider beneath PlacementManager.
    pub fn with_benchmark_reset_provider(
        mut self,
        provider: Arc<dyn PlacementBenchmarkResetProvider>,
    ) -> Self {
        self.benchmark_resets = Some(provider);
        self
    }

    // Allocates, stages, and persists one complete placement group.
    pub fn stage(&self, request: PlacementRequest) -> Result<PlacementChange, PlacementError> {
        self.lifecycle.stage(request)
    }

    // Starts every runtime-declared phase and publishes one complete endpoint.
    pub fn start(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        self.lifecycle.start(placement_group_id)
    }

    // Stops the complete group while retaining its exact resource reservations.
    pub fn stop(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        self.lifecycle.stop(placement_group_id)
    }

    // Recovers the complete failed group under one explicit protection decision.
    pub fn recover(
        &self,
        placement_group_id: &PlacementGroupId,
        acknowledge_protection_trips: bool,
    ) -> Result<PlacementChange, PlacementError> {
        self.lifecycle
            .recover(placement_group_id, acknowledge_protection_trips)
    }

    // Removes every placement and releases only this group's exact resources.
    pub fn remove(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        self.lifecycle.remove(placement_group_id)
    }

    // Reconciles current node observations into one atomic group snapshot.
    pub fn reconcile(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<PlacementChange, PlacementError> {
        self.lifecycle.reconcile(placement_group_id)
    }

    // Captures one exact resident process/store snapshot before benchmark mutation begins.
    pub fn prepare_benchmark_isolation(
        &self,
        request: PlacementBenchmarkIsolationRequest,
    ) -> Result<PlacementBenchmarkIsolationReceipt, PlacementError> {
        let provider = self
            .benchmark_resets
            .as_ref()
            .ok_or(PlacementError::ExecutionUnavailable)?;
        let current = self
            .store
            .read(request.placement_group_id())?
            .ok_or(PlacementError::GroupNotFound)?;
        if current.record().group().state() != li_core_interface::PlacementGroupState::Running {
            return Err(PlacementError::InvalidTransition);
        }
        let receipt = provider.prepare_isolation(&request, &current)?;
        if receipt.request() != &request || receipt.prepared_revision() != current.revision() {
            return Err(PlacementError::StoreConflict);
        }
        Ok(receipt)
    }

    // Resets one running group to a proven fresh process and empty prefix-store generation.
    pub fn reset_for_benchmark(
        &self,
        request: PlacementBenchmarkResetRequest,
    ) -> Result<PlacementBenchmarkResetReceipt, PlacementError> {
        let provider = self
            .benchmark_resets
            .as_ref()
            .ok_or(PlacementError::ExecutionUnavailable)?;
        let isolation = provider
            .active_isolation(request.placement_group_id())?
            .ok_or(PlacementError::StoreConflict)?;
        if isolation.request().placement_group_id() != request.placement_group_id()
            || isolation.prepared_revision() > request.expected_revision()
            || provider.restoration_receipt(isolation.request())?.is_some()
        {
            return Err(PlacementError::StoreConflict);
        }
        if let Some(receipt) = provider.receipt(request.reset_id())? {
            let current = self
                .store
                .read(request.placement_group_id())?
                .ok_or(PlacementError::GroupNotFound)?;
            if !request.matches_receipt(&receipt)
                || current.revision() != receipt.next_revision()
                || current.record().group().state()
                    != li_core_interface::PlacementGroupState::Running
            {
                return Err(PlacementError::StoreConflict);
            }
            return Ok(receipt);
        }
        let previous = self
            .store
            .read(request.placement_group_id())?
            .ok_or(PlacementError::GroupNotFound)?;
        if previous.revision() != request.expected_revision()
            || previous.record().group().state() != li_core_interface::PlacementGroupState::Running
        {
            return Err(PlacementError::StoreConflict);
        }
        let previous_generations = provider.generations(&request, &previous)?;
        let stopped = self.stop(request.placement_group_id())?;
        let store_generation = provider.reset_store(&request, stopped.record())?;
        if &store_generation == previous_generations.store_generation_sha256() {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let running = self.start(request.placement_group_id())?;
        if running.record().record().group().state()
            != li_core_interface::PlacementGroupState::Running
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let process_generation = match provider.process_generation(&request, running.record()) {
            Ok(generation) => generation,
            Err(error) => {
                let _ = self.stop(request.placement_group_id());
                return Err(error);
            }
        };
        if &process_generation == previous_generations.process_generation_sha256() {
            let _ = self.stop(request.placement_group_id());
            return Err(PlacementError::ExecutionUnavailable);
        }
        let reset_at = match self.clock.now() {
            Ok(reset_at) => reset_at,
            Err(error) => {
                let _ = self.stop(request.placement_group_id());
                return Err(error);
            }
        };
        let receipt = PlacementBenchmarkResetReceipt::new(
            &request,
            previous.revision(),
            running.record().revision(),
            store_generation,
            process_generation,
            reset_at,
        )?;
        match provider.commit(receipt.clone()) {
            Ok(committed) if committed == receipt => Ok(committed),
            Ok(_) => {
                let _ = self.stop(request.placement_group_id());
                Err(PlacementError::StoreConflict)
            }
            Err(error) => {
                let _ = self.stop(request.placement_group_id());
                Err(error)
            }
        }
    }

    // Restores the exact resident store and restarts its complete placement group idempotently.
    pub fn restore_benchmark_isolation(
        &self,
        request: PlacementBenchmarkIsolationRequest,
    ) -> Result<PlacementBenchmarkRestorationReceipt, PlacementError> {
        let provider = self
            .benchmark_resets
            .as_ref()
            .ok_or(PlacementError::ExecutionUnavailable)?;
        if let Some(receipt) = provider.restoration_receipt(&request)? {
            let current = self
                .store
                .read(request.placement_group_id())?
                .ok_or(PlacementError::GroupNotFound)?;
            if receipt.isolation().request() != &request
                || current.revision() != receipt.next_revision()
                || current.record().group().state()
                    != li_core_interface::PlacementGroupState::Running
            {
                return Err(PlacementError::StoreConflict);
            }
            return Ok(receipt);
        }
        let isolation = provider
            .isolation_receipt(&request)?
            .ok_or(PlacementError::StoreConflict)?;
        if isolation.request() != &request {
            return Err(PlacementError::StoreConflict);
        }
        let stopped = self.stop(request.placement_group_id())?;
        if stopped.record().record().group().state()
            != li_core_interface::PlacementGroupState::Stopped
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let store_generation = provider.restore_store(&request, stopped.record())?;
        if &store_generation != isolation.resident_store_generation_sha256() {
            return Err(PlacementError::StoreConflict);
        }
        let running = self.start(request.placement_group_id())?;
        if running.record().record().group().state()
            != li_core_interface::PlacementGroupState::Running
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let process_generation =
            match provider.restored_process_generation(&request, running.record()) {
                Ok(generation) => generation,
                Err(error) => {
                    let _ = self.stop(request.placement_group_id());
                    return Err(error);
                }
            };
        if &process_generation == isolation.resident_process_generation_sha256() {
            let _ = self.stop(request.placement_group_id());
            return Err(PlacementError::ExecutionUnavailable);
        }
        let restored_at = match self.clock.now() {
            Ok(restored_at) => restored_at,
            Err(error) => {
                let _ = self.stop(request.placement_group_id());
                return Err(error);
            }
        };
        let receipt = PlacementBenchmarkRestorationReceipt::new(
            isolation,
            stopped.record().revision(),
            running.record().revision(),
            process_generation,
            restored_at,
        )?;
        match provider.commit_restoration(receipt.clone()) {
            Ok(committed) if committed == receipt => Ok(committed),
            Ok(_) => {
                let _ = self.stop(request.placement_group_id());
                Err(PlacementError::StoreConflict)
            }
            Err(error) => {
                let _ = self.stop(request.placement_group_id());
                Err(error)
            }
        }
    }

    // Reads one bounded opaque runtime-log batch from the exact endpoint-owner placement.
    pub fn read_logs(
        &self,
        request: PlacementLogReadRequest,
    ) -> Result<PlacementLogBatch, PlacementError> {
        li_placement_log::read_placement_logs(
            &self.store,
            self.logs
                .as_ref()
                .ok_or(PlacementError::ExecutionUnavailable)?,
            request,
        )
    }
}
