// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_benchmark_manager::{
    BenchmarkClock, BenchmarkCommunityVerificationDocumentProvider, BenchmarkError,
    BenchmarkEvidenceNativeIo, BenchmarkExecutionProvider, BenchmarkPublicationProvider,
    BenchmarkRunPlanProvider, BenchmarkRunPlanSource, BenchmarkSigningProvider, BenchmarkStore,
    BenchmarkTelemetryProvider, BenchmarkVerificationHandoffProvider,
    BoundBenchmarkAuthorizationProvider, CoordinatedBenchmarkExecutionProvider,
    DatabaseBenchmarkStore, DatabaseBenchmarkVerificationStore,
    FilesystemBenchmarkEvidenceProvider, OpensslBenchmarkSigningProvider,
    PairedBenchmarkVerificationExecutionProvider, ResolvedBenchmarkRunPlanProvider,
    RoutedBenchmarkEvidenceProvider, SystemBenchmarkClock, SystemBenchmarkEvidenceNativeIo,
    SystemBenchmarkSigningCommandRunner, SystemBenchmarkVerificationClock,
    WindowedBenchmarkTelemetryProvider,
};
use li_benchmark_worker::NativeBenchmarkWatchdogInput;
use li_database::DatabaseManager;
use li_node_manager::{NodeBenchmarkCoordinator, NodeManager};
use li_placement_manager::{PlacementCredentialReader, PlacementManager, PlacementStore};
use li_runtime_manager::{
    RuntimeExecutionManifestProvider, RuntimeInstallationStore, RuntimeManager,
};

use crate::{
    compose_core_node_benchmark, compose_core_node_benchmark_with_execution,
    ApplicationBenchmarkAuthorizationSource, ApplicationBenchmarkExecutionScheduler,
    ApplicationBenchmarkIsolationPort, ApplicationBenchmarkRequestProvider,
    ApplicationBenchmarkRunPlanSource, ApplicationBenchmarkTelemetryPort,
    ApplicationCoreBenchmarkExecutionRouter, ApplicationCoreBenchmarkVerificationChildProvider,
    CoreBenchmarkCommunityAuthorityPort, CoreBenchmarkPortError,
    CoreBenchmarkTelemetryObservationPort, FilesystemCoreBenchmarkTelemetryPersistence,
    SystemCoreBenchmarkTaskPort,
};

const MAXIMUM_BENCHMARK_RUNTIME_MILLISECONDS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAXIMUM_BENCHMARK_STOP_GRACE_MILLISECONDS: u64 = 10 * 60 * 1000;

// Names one production benchmark composition failure without native path or provider detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreBenchmarkCompositionError {
    InvalidConfiguration,
    Benchmark(BenchmarkError),
    Port(CoreBenchmarkPortError),
}

impl fmt::Display for CoreBenchmarkCompositionError {
    // Presents stable composition language without leaking credentials or filesystem layout.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("benchmark production configuration is invalid")
            }
            Self::Benchmark(error) => write!(formatter, "{error}"),
            Self::Port(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CoreBenchmarkCompositionError {}

impl From<BenchmarkError> for CoreBenchmarkCompositionError {
    // Preserves the stable manager/provider category at the production boundary.
    fn from(error: BenchmarkError) -> Self {
        Self::Benchmark(error)
    }
}

impl From<CoreBenchmarkPortError> for CoreBenchmarkCompositionError {
    // Preserves the stable Application-port category at the production boundary.
    fn from(error: CoreBenchmarkPortError) -> Self {
        Self::Port(error)
    }
}

// Carries every owner-bound native path and deadline used by the benchmark lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationCoreBenchmarkConfiguration {
    worker_executable: PathBuf,
    task_root: PathBuf,
    telemetry_root: PathBuf,
    evidence_root: PathBuf,
    signing_workspace_root: PathBuf,
    openssl_executable: PathBuf,
    signing_private_key: PathBuf,
    signing_public_key: PathBuf,
    watchdog: NativeBenchmarkWatchdogInput,
    owner_user_id: u32,
    maximum_runtime_milliseconds: u64,
    stop_grace_milliseconds: u64,
}

impl ApplicationCoreBenchmarkConfiguration {
    // Creates one closed filesystem and scheduling contract before any provider is composed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_executable: PathBuf,
        task_root: PathBuf,
        telemetry_root: PathBuf,
        evidence_root: PathBuf,
        signing_workspace_root: PathBuf,
        openssl_executable: PathBuf,
        signing_private_key: PathBuf,
        signing_public_key: PathBuf,
        watchdog: NativeBenchmarkWatchdogInput,
        owner_user_id: u32,
        maximum_runtime_milliseconds: u64,
        stop_grace_milliseconds: u64,
    ) -> Result<Self, CoreBenchmarkCompositionError> {
        let paths = [
            worker_executable.as_path(),
            task_root.as_path(),
            telemetry_root.as_path(),
            evidence_root.as_path(),
            signing_workspace_root.as_path(),
            openssl_executable.as_path(),
            signing_private_key.as_path(),
            signing_public_key.as_path(),
        ];
        let roots = [
            task_root.as_path(),
            telemetry_root.as_path(),
            evidence_root.as_path(),
            signing_workspace_root.as_path(),
        ];
        let immutable_files = [
            worker_executable.as_path(),
            openssl_executable.as_path(),
            signing_private_key.as_path(),
            signing_public_key.as_path(),
        ];
        if paths.iter().any(|path| !is_absolute_normal_path(path))
            || !paths_are_disjoint(&roots)
            || roots.iter().any(|root| {
                immutable_files
                    .iter()
                    .any(|immutable| immutable.starts_with(root))
            })
            || signing_private_key == signing_public_key
            || maximum_runtime_milliseconds == 0
            || maximum_runtime_milliseconds > MAXIMUM_BENCHMARK_RUNTIME_MILLISECONDS
            || stop_grace_milliseconds == 0
            || stop_grace_milliseconds > MAXIMUM_BENCHMARK_STOP_GRACE_MILLISECONDS
            || stop_grace_milliseconds > maximum_runtime_milliseconds
        {
            return Err(CoreBenchmarkCompositionError::InvalidConfiguration);
        }
        Ok(Self {
            worker_executable,
            task_root,
            telemetry_root,
            evidence_root,
            signing_workspace_root,
            openssl_executable,
            signing_private_key,
            signing_public_key,
            watchdog,
            owner_user_id,
            maximum_runtime_milliseconds,
            stop_grace_milliseconds,
        })
    }
}

// Supplies the exact existing manager graph and read capabilities shared by benchmark execution.
pub struct ApplicationCoreBenchmarkManagers {
    database: Arc<DatabaseManager>,
    node: Arc<NodeManager>,
    runtime: Arc<RuntimeManager>,
    runtime_store: Arc<dyn RuntimeInstallationStore>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
    placement: Arc<PlacementManager>,
    placement_store: Arc<dyn PlacementStore>,
    credentials: Arc<dyn PlacementCredentialReader>,
}

impl ApplicationCoreBenchmarkManagers {
    // Creates one immutable manager graph without discovering or replacing any dependency.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: Arc<DatabaseManager>,
        node: Arc<NodeManager>,
        runtime: Arc<RuntimeManager>,
        runtime_store: Arc<dyn RuntimeInstallationStore>,
        executions: Arc<dyn RuntimeExecutionManifestProvider>,
        placement: Arc<PlacementManager>,
        placement_store: Arc<dyn PlacementStore>,
        credentials: Arc<dyn PlacementCredentialReader>,
    ) -> Self {
        Self {
            database,
            node,
            runtime,
            runtime_store,
            executions,
            placement,
            placement_store,
            credentials,
        }
    }
}

// Supplies only authorities that have no truthful generic native implementation.
pub struct ApplicationCoreBenchmarkPorts {
    community: Arc<dyn CoreBenchmarkCommunityAuthorityPort>,
    telemetry_observations: Arc<dyn CoreBenchmarkTelemetryObservationPort>,
}

// Supplies the two leaf capabilities required only by paired community verification.
pub struct ApplicationCoreBenchmarkVerificationComposition {
    handoff: Arc<dyn BenchmarkVerificationHandoffProvider>,
    publication: Arc<dyn ApplicationCoreBenchmarkVerificationPublicationFactory>,
}

// Builds the terminal evidence and publisher pair only after the paired result source exists.
pub trait ApplicationCoreBenchmarkVerificationPublicationFactory: Send + Sync {
    // Returns one terminal pair bound to the exact parent paired result source.
    fn terminal_providers(
        &self,
        results: Arc<PairedBenchmarkVerificationExecutionProvider>,
    ) -> Result<ApplicationCoreBenchmarkVerificationTerminalProviders, BenchmarkError>;
}

// Carries the two terminal providers that share one persisted community record.
pub struct ApplicationCoreBenchmarkVerificationTerminalProviders {
    evidence: Arc<dyn BenchmarkCommunityVerificationDocumentProvider>,
    publication: Arc<dyn BenchmarkPublicationProvider>,
}

impl ApplicationCoreBenchmarkVerificationTerminalProviders {
    // Creates one closed evidence/publication pair without exposing its material provider.
    pub const fn new(
        evidence: Arc<dyn BenchmarkCommunityVerificationDocumentProvider>,
        publication: Arc<dyn BenchmarkPublicationProvider>,
    ) -> Self {
        Self {
            evidence,
            publication,
        }
    }

    // Exposes the composed pair only to the crate's end-to-end production composition test.
    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Arc<dyn BenchmarkCommunityVerificationDocumentProvider>,
        Arc<dyn BenchmarkPublicationProvider>,
    ) {
        (self.evidence, self.publication)
    }
}

impl ApplicationCoreBenchmarkVerificationComposition {
    // Creates one parent composition from Node handoff and terminal GitHub publication leaves.
    pub const fn new(
        handoff: Arc<dyn BenchmarkVerificationHandoffProvider>,
        publication: Arc<dyn ApplicationCoreBenchmarkVerificationPublicationFactory>,
    ) -> Self {
        Self {
            handoff,
            publication,
        }
    }
}

impl ApplicationCoreBenchmarkPorts {
    // Creates one explicit external-authority boundary without a permissive fallback.
    pub const fn new(
        community: Arc<dyn CoreBenchmarkCommunityAuthorityPort>,
        telemetry_observations: Arc<dyn CoreBenchmarkTelemetryObservationPort>,
    ) -> Self {
        Self {
            community,
            telemetry_observations,
        }
    }
}

// Composes the production Node-owned benchmark lifecycle without performing lifecycle mutation.
pub fn compose_system_core_benchmark(
    configuration: ApplicationCoreBenchmarkConfiguration,
    managers: ApplicationCoreBenchmarkManagers,
    ports: ApplicationCoreBenchmarkPorts,
) -> Result<NodeBenchmarkCoordinator, CoreBenchmarkCompositionError> {
    compose_system_core_benchmark_internal(configuration, managers, ports, None)
}

// Composes local and paired verification execution behind one BenchmarkManager lifecycle.
pub fn compose_system_core_benchmark_with_verification(
    configuration: ApplicationCoreBenchmarkConfiguration,
    managers: ApplicationCoreBenchmarkManagers,
    ports: ApplicationCoreBenchmarkPorts,
    verification: ApplicationCoreBenchmarkVerificationComposition,
) -> Result<NodeBenchmarkCoordinator, CoreBenchmarkCompositionError> {
    compose_system_core_benchmark_internal(configuration, managers, ports, Some(verification))
}

// Composes shared providers once, then selects ordinary or routed execution at the final root.
fn compose_system_core_benchmark_internal(
    configuration: ApplicationCoreBenchmarkConfiguration,
    managers: ApplicationCoreBenchmarkManagers,
    ports: ApplicationCoreBenchmarkPorts,
    verification: Option<ApplicationCoreBenchmarkVerificationComposition>,
) -> Result<NodeBenchmarkCoordinator, CoreBenchmarkCompositionError> {
    let core_installation_id = managers
        .node
        .local_node()
        .map_err(|_| CoreBenchmarkCompositionError::InvalidConfiguration)?
        .identity()
        .installation_id()
        .clone();
    let source: Arc<dyn BenchmarkRunPlanSource> = Arc::new(ApplicationBenchmarkRunPlanSource::new(
        core_installation_id,
        managers.runtime.clone(),
        managers.runtime_store.clone(),
        managers.placement_store.clone(),
        configuration.maximum_runtime_milliseconds,
        configuration.stop_grace_milliseconds,
    )?);
    let plans: Arc<dyn BenchmarkRunPlanProvider> =
        Arc::new(ResolvedBenchmarkRunPlanProvider::new(source));
    let database = managers.database.clone();
    let store: Arc<dyn BenchmarkStore> = Arc::new(DatabaseBenchmarkStore::new(managers.database));
    let requests = Arc::new(ApplicationBenchmarkRequestProvider::new(
        managers.node.clone(),
        managers.runtime,
        managers.runtime_store.clone(),
        managers.placement_store.clone(),
    ));
    let authorization = Arc::new(ApplicationBenchmarkAuthorizationSource::new(
        managers.node,
        ports.community,
    ));
    let isolation = Arc::new(ApplicationBenchmarkIsolationPort::new(
        managers.placement.clone(),
    ));
    let tasks = Arc::new(SystemCoreBenchmarkTaskPort::new(
        configuration.worker_executable,
        configuration.task_root.clone(),
        configuration.owner_user_id,
        store.clone(),
        plans.clone(),
        managers.runtime_store,
        managers.executions,
        managers.placement_store,
        managers.credentials,
        managers.placement,
        configuration.watchdog,
    )?);
    let telemetry = Arc::new(FilesystemCoreBenchmarkTelemetryPersistence::new(
        configuration.telemetry_root,
        configuration.owner_user_id,
    )?);
    let native_io: Arc<dyn BenchmarkEvidenceNativeIo> = Arc::new(SystemBenchmarkEvidenceNativeIo);
    let evidence = Arc::new(FilesystemBenchmarkEvidenceProvider::new(
        configuration.task_root,
        configuration.evidence_root.clone(),
        configuration.owner_user_id,
        native_io.clone(),
    )?);
    evidence.preflight()?;
    let signing = Arc::new(OpensslBenchmarkSigningProvider::new(
        configuration.openssl_executable,
        configuration.signing_private_key,
        configuration.signing_public_key,
        configuration.evidence_root,
        configuration.signing_workspace_root,
        configuration.owner_user_id,
        native_io,
        Arc::new(SystemBenchmarkSigningCommandRunner),
    )?);
    signing.preflight()?;
    let clock: Arc<dyn BenchmarkClock> = Arc::new(SystemBenchmarkClock);
    match verification {
        None => Ok(compose_core_node_benchmark(
            store,
            requests,
            authorization,
            plans,
            isolation,
            tasks,
            ports.telemetry_observations,
            telemetry,
            evidence,
            signing as Arc<dyn BenchmarkSigningProvider>,
            clock,
        )),
        Some(verification) => {
            let local_execution: Arc<dyn BenchmarkExecutionProvider> =
                Arc::new(CoordinatedBenchmarkExecutionProvider::new(
                    plans.clone(),
                    Arc::new(ApplicationBenchmarkExecutionScheduler::new(
                        isolation, tasks,
                    )),
                    clock.clone(),
                ));
            let telemetry_provider: Arc<dyn BenchmarkTelemetryProvider> =
                Arc::new(WindowedBenchmarkTelemetryProvider::new(
                    plans.clone(),
                    Arc::new(ApplicationBenchmarkTelemetryPort::new(
                        ports.telemetry_observations,
                        telemetry,
                    )),
                    clock.clone(),
                ));
            let verification_store = Arc::new(DatabaseBenchmarkVerificationStore::new(database));
            let child = Arc::new(ApplicationCoreBenchmarkVerificationChildProvider::new(
                Arc::new(BoundBenchmarkAuthorizationProvider::new(
                    authorization.clone(),
                )),
                plans,
                local_execution.clone(),
                telemetry_provider.clone(),
                evidence.clone(),
                signing.clone(),
            ));
            let paired = Arc::new(PairedBenchmarkVerificationExecutionProvider::new(
                verification_store.clone(),
                verification.handoff,
                child,
                Arc::new(SystemBenchmarkVerificationClock),
            ));
            let terminal = verification
                .publication
                .terminal_providers(paired.clone())?;
            let outer_evidence: Arc<dyn li_benchmark_manager::BenchmarkEvidenceProvider> =
                Arc::new(RoutedBenchmarkEvidenceProvider::new(
                    evidence.clone(),
                    evidence.clone(),
                    terminal.evidence,
                ));
            let routed: Arc<dyn BenchmarkExecutionProvider> =
                Arc::new(ApplicationCoreBenchmarkExecutionRouter::new(
                    local_execution,
                    paired,
                    verification_store,
                ));
            Ok(compose_core_node_benchmark_with_execution(
                store,
                requests,
                authorization,
                routed,
                telemetry_provider,
                outer_evidence,
                signing,
                terminal.publication,
                clock,
            ))
        }
    }
}

// Returns whether one path is absolute and contains no relative or parent traversal component.
fn is_absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Requires every owner root to have one non-overlapping lifecycle namespace.
fn paths_are_disjoint(paths: &[&Path]) -> bool {
    paths.iter().enumerate().all(|(index, path)| {
        paths
            .iter()
            .skip(index + 1)
            .all(|other| !path.starts_with(other) && !other.starts_with(path))
    })
}
