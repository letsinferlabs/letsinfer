// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use li_placement_manager::{
    DockerLinuxPlacementExecutionProvider, DockerLinuxPlacementLogProvider,
    FilesystemLinuxPlacementProtectionProvider, FilesystemPlacementBenchmarkResetProvider,
    FilesystemPlacementCredentialProvider, FilesystemPlacementCredentialReader,
    FilesystemPlacementMaterialProvider, FilesystemPlacementMaterialReader,
    LinuxPlacementBenchmarkProcessProvider, LinuxPlacementExecutor,
    LinuxRuntimePlacementEnvironment, MacosRuntimePlacementEnvironment,
    OpenSslPlacementTlsMaterialProvider, PlacementAdmissionPolicy,
    PlacementBenchmarkProcessProvider, PlacementCredentialReader, PlacementError,
    PlacementExecutor, PlacementManager, PlacementRuntimeLogProvider, PlacementStore,
    PollingLinuxContainerReadinessProvider, ProcfsLinuxProcessIdentityProvider,
    RandomPlacementSecretMaterialProvider, RuntimeManagerPlacementExecutionAdapter,
    RuntimePlacementLaunchPlanResolver, ShellFreeCommand,
    StoredPlacementLaunchPlanIdentityProvider, SystemDockerClient, SystemLinuxPlacementWaiter,
    SystemLinuxProcessIdentityIo, SystemLinuxProtectionIo, SystemPlacementClock,
    SystemPlacementEndpointReadinessProvider, SystemPlacementIdentityProvider,
    SystemPlacementMaterialIdentityProvider, SystemPlacementMaterialIo, SystemPlacementSecretIo,
    SystemPlacementTlsWorkspaceIo, SystemProtectionGenerationProvider,
    SystemShellFreeCommandRunner,
};
use li_runtime_manager::RuntimeExecutionManifestProvider;

#[cfg(target_os = "macos")]
use li_placement_manager::{
    FilesystemMacosPlacementLogProvider, MacosPlacementExecutor, SystemMacosLaunchAgentIo,
    SystemMacosLaunchAgentService, SystemMacosPlacementWaiter,
};

// Selects the exact native execution capabilities owned by one Node process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreModelPlacementPlatformInput {
    Linux {
        docker_command: PathBuf,
        protection_root: PathBuf,
        user_id: u32,
        group_id: u32,
    },
    Macos {
        launch_agents_root: PathBuf,
        launchctl_command: PathBuf,
    },
}

// Carries all shared paths and bounds required by production PlacementManager composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreModelPlacementCompositionInput {
    pub owner_user_id: u32,
    pub material_root: PathBuf,
    pub runtime_cache_root: PathBuf,
    pub secret_root: PathBuf,
    pub tls_workspace_root: PathBuf,
    pub openssl_command: PathBuf,
    pub command_working_directory: PathBuf,
    pub endpoint_timeout: Duration,
    pub maximum_hardware_age: Duration,
    pub platform: CoreModelPlacementPlatformInput,
}

// Retains one placement manager and the private credential reader shared by benchmark execution.
pub struct CoreModelPlacementComposition {
    manager: Arc<PlacementManager>,
    credentials: Arc<dyn PlacementCredentialReader>,
}

impl CoreModelPlacementComposition {
    // Returns the complete production PlacementManager without exposing native provider detail.
    pub fn manager(&self) -> Arc<PlacementManager> {
        self.manager.clone()
    }

    // Returns the same owner-private credential reader used to materialize placement endpoints.
    pub fn credentials(&self) -> Arc<dyn PlacementCredentialReader> {
        self.credentials.clone()
    }
}

// Composes credentials, sealed launch material, native execution, and durable allocation.
pub fn compose_core_model_placement(
    input: CoreModelPlacementCompositionInput,
    store: Arc<dyn PlacementStore>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
) -> Result<CoreModelPlacementComposition, PlacementError> {
    let runner = Arc::new(SystemShellFreeCommandRunner);
    let identities = Arc::new(SystemPlacementMaterialIdentityProvider);
    let openssl = ShellFreeCommand::new(
        input.openssl_command,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        input.command_working_directory.clone(),
    )?;
    let tls = Arc::new(OpenSslPlacementTlsMaterialProvider::new(
        openssl,
        input.tls_workspace_root,
        input.owner_user_id,
        runner.clone(),
        Arc::new(SystemPlacementTlsWorkspaceIo),
        identities.clone(),
    )?);
    let secret_io = Arc::new(SystemPlacementSecretIo);
    let credential_reader: Arc<dyn PlacementCredentialReader> =
        Arc::new(FilesystemPlacementCredentialReader::new(
            input.secret_root.clone(),
            input.owner_user_id,
            secret_io.clone(),
        )?);
    let credentials = Arc::new(FilesystemPlacementCredentialProvider::new(
        input.secret_root,
        input.owner_user_id,
        secret_io,
        Arc::new(RandomPlacementSecretMaterialProvider::new(tls)),
        identities.clone(),
    )?);
    let (linux, macos) = match &input.platform {
        CoreModelPlacementPlatformInput::Linux {
            docker_command,
            user_id,
            group_id,
            ..
        } => (
            Some(LinuxRuntimePlacementEnvironment::ordinary(
                ShellFreeCommand::new(
                    docker_command.clone(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    input.command_working_directory.clone(),
                )?,
                *user_id,
                *group_id,
            )?),
            None,
        ),
        CoreModelPlacementPlatformInput::Macos { .. } => {
            (None, Some(MacosRuntimePlacementEnvironment::new()))
        }
    };
    let runtime_execution = Arc::new(RuntimeManagerPlacementExecutionAdapter::new(
        executions, linux, macos,
    ));
    let resolver = Arc::new(RuntimePlacementLaunchPlanResolver::new(runtime_execution));
    let material_root = input.material_root.clone();
    let plan_identities = Arc::new(StoredPlacementLaunchPlanIdentityProvider::new(
        store.clone(),
    ));
    let material_reader = FilesystemPlacementMaterialReader::new(
        material_root.clone(),
        input.owner_user_id,
        Arc::new(SystemPlacementMaterialIo),
        plan_identities.clone(),
    )?;
    let material = Arc::new(
        FilesystemPlacementMaterialProvider::new(
            material_root.clone(),
            input.owner_user_id,
            Arc::new(SystemPlacementMaterialIo),
            resolver,
            identities,
            plan_identities,
            credentials.clone(),
        )?
        .with_cache_root(input.runtime_cache_root.clone())?,
    );
    let endpoints = Arc::new(SystemPlacementEndpointReadinessProvider::new(
        input.endpoint_timeout,
    )?);
    let (executor, logs, benchmark_processes): (
        Arc<dyn PlacementExecutor>,
        Option<Arc<dyn PlacementRuntimeLogProvider>>,
        Arc<dyn PlacementBenchmarkProcessProvider>,
    ) = match input.platform {
        CoreModelPlacementPlatformInput::Linux {
            docker_command,
            protection_root,
            ..
        } => {
            let docker = Arc::new(SystemDockerClient::new(runner.clone()));
            let waiter = Arc::new(SystemLinuxPlacementWaiter);
            let readiness = Arc::new(PollingLinuxContainerReadinessProvider::new(
                endpoints,
                waiter.clone(),
            ));
            let execution = Arc::new(DockerLinuxPlacementExecutionProvider::new(
                material.clone(),
                docker.clone(),
                Arc::new(ProcfsLinuxProcessIdentityProvider::new(Arc::new(
                    SystemLinuxProcessIdentityIo,
                ))),
                readiness,
            ));
            let benchmark_processes = Arc::new(LinuxPlacementBenchmarkProcessProvider::new(
                execution.clone(),
            ));
            let logs = Arc::new(DockerLinuxPlacementLogProvider::new(
                material, docker, waiter,
            ));
            let protection = Arc::new(FilesystemLinuxPlacementProtectionProvider::new(
                protection_root,
                input.owner_user_id,
                100,
                Duration::from_millis(10),
                Arc::new(SystemLinuxProtectionIo::default()),
                Arc::new(SystemProtectionGenerationProvider),
            )?);
            let _ = docker_command;
            (
                Arc::new(LinuxPlacementExecutor::new(execution, protection)),
                Some(logs),
                benchmark_processes,
            )
        }
        CoreModelPlacementPlatformInput::Macos {
            launch_agents_root,
            launchctl_command,
            ..
        } => {
            #[cfg(target_os = "macos")]
            {
                let launchctl = ShellFreeCommand::new(
                    launchctl_command,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    input.command_working_directory,
                )?;
                let benchmark_processes = Arc::new(
                    crate::li_core_gateway_macos_safety::SystemCoreMacosPlacementBenchmarkProcessProvider::new(
                        input.owner_user_id,
                        launch_agents_root.clone(),
                        material_reader,
                        launchctl.clone(),
                        runner.clone(),
                    ),
                );
                let io = Arc::new(SystemMacosLaunchAgentIo::default());
                let launchd = Arc::new(SystemMacosLaunchAgentService::new(
                    launch_agents_root,
                    input.owner_user_id,
                    launchctl,
                    runner,
                    io.clone(),
                )?);
                let waiter = Arc::new(SystemMacosPlacementWaiter);
                let logs = Arc::new(FilesystemMacosPlacementLogProvider::new(
                    material.clone(),
                    io,
                    waiter.clone(),
                    input.owner_user_id,
                ));
                (
                    Arc::new(MacosPlacementExecutor::new(
                        material, launchd, endpoints, waiter,
                    )),
                    Some(logs),
                    benchmark_processes,
                )
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (
                    launch_agents_root,
                    launchctl_command,
                    material_reader,
                    endpoints,
                    runner,
                );
                return Err(PlacementError::ExecutionUnavailable);
            }
        }
    };
    let admission = PlacementAdmissionPolicy::new(input.maximum_hardware_age)?;
    let manager = PlacementManager::new(
        store,
        executor,
        Arc::new(SystemPlacementIdentityProvider),
        Arc::new(SystemPlacementClock),
        admission,
    );
    let benchmark_state_root = material_root
        .parent()
        .ok_or(PlacementError::ExecutionUnavailable)?
        .join("benchmark_isolation");
    let manager = manager.with_benchmark_reset_provider(Arc::new(
        FilesystemPlacementBenchmarkResetProvider::new(
            benchmark_state_root,
            input.runtime_cache_root,
            input.owner_user_id,
            benchmark_processes,
        )?,
    ));
    let manager = Arc::new(match logs {
        Some(logs) => manager.with_log_provider(logs),
        None => manager,
    });
    Ok(CoreModelPlacementComposition {
        manager,
        credentials: credential_reader,
    })
}
