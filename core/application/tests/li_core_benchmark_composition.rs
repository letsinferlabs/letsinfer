// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_benchmark_manager::{
    BenchmarkCommunityAuthority, BenchmarkError, BenchmarkRequest, BenchmarkStore,
    DatabaseBenchmarkStore,
};
use li_benchmark_worker::NativeBenchmarkWatchdogInput;
use li_core_application::{
    compose_system_core_benchmark, ApplicationCoreBenchmarkConfiguration,
    ApplicationCoreBenchmarkManagers, ApplicationCoreBenchmarkPorts,
    CoreBenchmarkCommunityAuthorityPort, CoreBenchmarkCompositionError, CoreBenchmarkPortError,
    CoreBenchmarkTelemetryObservation, CoreBenchmarkTelemetryObservationPort,
    CoreBenchmarkTelemetryWindow,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, OperationId, Placement, PlacementEndpoint,
    RuntimeInstallationId, Sha256Digest, UnixMilliseconds,
};
use li_database::{DatabaseConfiguration, DatabaseManager};
use li_node_manager::{DatabasePlacementStore, DatabaseRuntimeInstallationStore, NodeManager};
use li_placement_manager::{
    PlacementAdmissionPolicy, PlacementCredentialReader, PlacementCredentialReferences,
    PlacementError, PlacementExecutor, PlacementManager, PlacementObservation, PlacementStore,
    SystemPlacementClock, SystemPlacementIdentityProvider,
};
use li_runtime_manager::{
    RuntimeCandidate, RuntimeCatalogProvider, RuntimeError, RuntimeExecutionManifest,
    RuntimeExecutionManifestProvider, RuntimeInstallationStore, RuntimeManager,
};

// Counts accidental construction-time access to injected external authorities.
#[derive(Default)]
struct ExternalCallCounter {
    calls: AtomicUsize,
}

impl ExternalCallCounter {
    // Returns the exact number of external capability calls.
    fn value(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

// Keeps community proposal authority explicit while rejecting accidental construction-time use.
struct CommunityAuthorityMock {
    counter: Arc<ExternalCallCounter>,
}

impl CoreBenchmarkCommunityAuthorityPort for CommunityAuthorityMock {
    // Records and rejects any attempt to resolve community authority during composition.
    fn authority(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, CoreBenchmarkPortError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(CoreBenchmarkPortError::Unavailable)
    }
}

// Keeps live telemetry ownership explicit while rejecting construction-time observation.
struct TelemetryObservationMock {
    counter: Arc<ExternalCallCounter>,
}

impl CoreBenchmarkTelemetryObservationPort for TelemetryObservationMock {
    // Records and rejects any attempt to sample live state during composition.
    fn observe(
        &self,
        _command: &CoreBenchmarkTelemetryWindow,
    ) -> Result<CoreBenchmarkTelemetryObservation, CoreBenchmarkPortError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(CoreBenchmarkPortError::Unavailable)
    }
}

// Keeps catalog ownership explicit while rejecting accidental candidate selection.
struct CatalogMock {
    counter: Arc<ExternalCallCounter>,
}

impl RuntimeCatalogProvider for CatalogMock {
    // Records and rejects catalog access because composition must not select a runtime.
    fn candidates(
        &self,
        _model: &li_core_interface::LogicalModelName,
    ) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(RuntimeError::CatalogUnavailable)
    }
}

// Keeps execution-manifest ownership explicit while rejecting construction-time reads.
struct ExecutionManifestMock {
    counter: Arc<ExternalCallCounter>,
}

impl RuntimeExecutionManifestProvider for ExecutionManifestMock {
    // Records and rejects manifest access because composition must not resolve a run plan.
    fn manifest(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(RuntimeError::ExecutionManifestUnavailable)
    }
}

// Keeps native placement execution explicit while rejecting every construction-time operation.
struct PlacementExecutorMock {
    counter: Arc<ExternalCallCounter>,
}

impl PlacementExecutor for PlacementExecutorMock {
    // Rejects staging because production composition must not stage work.
    fn stage(&self, _placement: &Placement) -> Result<Sha256Digest, PlacementError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(PlacementError::ExecutionUnavailable)
    }

    // Rejects startup because production composition must not start work.
    fn start(
        &self,
        _placement: &Placement,
        _acknowledge_protection_trip: bool,
    ) -> Result<Option<PlacementEndpoint>, PlacementError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(PlacementError::ExecutionUnavailable)
    }

    // Rejects stop because production composition must not stop work.
    fn stop(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(PlacementError::ExecutionUnavailable)
    }

    // Rejects removal because production composition must not remove work.
    fn remove(&self, _placement: &Placement) -> Result<(), PlacementError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(PlacementError::ExecutionUnavailable)
    }

    // Rejects observation because production composition must not inspect native work.
    fn observe(&self, _placement: &Placement) -> Result<PlacementObservation, PlacementError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(PlacementError::ExecutionUnavailable)
    }
}

// Keeps placement credentials explicit while rejecting construction-time secret reads.
struct CredentialReaderMock {
    counter: Arc<ExternalCallCounter>,
}

impl PlacementCredentialReader for CredentialReaderMock {
    // Records and rejects credential access because composition must not inspect secrets.
    fn existing(
        &self,
        _placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        self.counter.calls.fetch_add(1, Ordering::SeqCst);
        Err(PlacementError::ExecutionUnavailable)
    }
}

// Retains one isolated concrete manager graph and owner-private production filesystem.
struct Fixture {
    _temporary: tempfile::TempDir,
    database: Arc<DatabaseManager>,
    node: Arc<NodeManager>,
    runtime: Arc<RuntimeManager>,
    runtime_store: Arc<dyn RuntimeInstallationStore>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
    placement: Arc<PlacementManager>,
    placement_store: Arc<dyn PlacementStore>,
    credentials: Arc<dyn PlacementCredentialReader>,
    community: Arc<dyn CoreBenchmarkCommunityAuthorityPort>,
    observations: Arc<dyn CoreBenchmarkTelemetryObservationPort>,
    counter: Arc<ExternalCallCounter>,
    worker: PathBuf,
    task_root: PathBuf,
    telemetry_root: PathBuf,
    evidence_root: PathBuf,
    signing_workspace_root: PathBuf,
    openssl: PathBuf,
    private_key: PathBuf,
    public_key: PathBuf,
    watchdog: NativeBenchmarkWatchdogInput,
    owner_user_id: u32,
}

impl Fixture {
    // Creates every real persistence and native-path prerequisite without lifecycle mutation.
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().canonicalize().expect("canonical root");
        let owner_user_id = unsafe { libc::geteuid() };
        let database = Arc::new(
            DatabaseManager::open(DatabaseConfiguration::new(root.join("core.sqlite3")))
                .expect("database"),
        );
        let node = Arc::new(
            NodeManager::open(
                database.clone(),
                local_node(),
                "initialize-benchmark-composition",
            )
            .expect("Node manager")
            .0,
        );
        let counter = Arc::new(ExternalCallCounter::default());
        let executions: Arc<dyn RuntimeExecutionManifestProvider> =
            Arc::new(ExecutionManifestMock {
                counter: counter.clone(),
            });
        let runtime = Arc::new(
            RuntimeManager::new(Arc::new(CatalogMock {
                counter: counter.clone(),
            }))
            .with_execution_provider(executions.clone()),
        );
        let runtime_store: Arc<dyn RuntimeInstallationStore> =
            Arc::new(DatabaseRuntimeInstallationStore::new(database.clone()));
        let placement_store: Arc<dyn PlacementStore> =
            Arc::new(DatabasePlacementStore::new(database.clone()));
        let placement = Arc::new(PlacementManager::new(
            placement_store.clone(),
            Arc::new(PlacementExecutorMock {
                counter: counter.clone(),
            }),
            Arc::new(SystemPlacementIdentityProvider),
            Arc::new(SystemPlacementClock),
            PlacementAdmissionPolicy::new(Duration::from_secs(60)).expect("admission"),
        ));
        let credentials: Arc<dyn PlacementCredentialReader> = Arc::new(CredentialReaderMock {
            counter: counter.clone(),
        });
        let community: Arc<dyn CoreBenchmarkCommunityAuthorityPort> =
            Arc::new(CommunityAuthorityMock {
                counter: counter.clone(),
            });
        let observations: Arc<dyn CoreBenchmarkTelemetryObservationPort> =
            Arc::new(TelemetryObservationMock {
                counter: counter.clone(),
            });
        let task_root = private_directory(&root, "tasks");
        let telemetry_root = private_directory(&root, "telemetry");
        let evidence_root = private_directory(&root, "evidence");
        let signing_workspace_root = private_directory(&root, "signing");
        let key_root = private_directory(&root, "keys");
        let worker = executable_file(&root, "li_benchmark_worker");
        let openssl = executable_file(&root, "openssl");
        let private_key = private_file(&key_root, "benchmark.key", b"private-key");
        let public_key = private_file(&key_root, "benchmark.pub", b"public-key");
        let watchdog = NativeBenchmarkWatchdogInput::new(
            "127.0.0.1".to_string(),
            9_445,
            "node.local".to_string(),
            key_root.join("watchdog-ca.pem"),
            key_root.join("watchdog-controller.pem"),
            key_root.join("watchdog-controller.key"),
            Duration::from_secs(5),
        )
        .expect("Watchdog configuration");
        Self {
            _temporary: temporary,
            database,
            node,
            runtime,
            runtime_store,
            executions,
            placement,
            placement_store,
            credentials,
            community,
            observations,
            counter,
            worker,
            task_root,
            telemetry_root,
            evidence_root,
            signing_workspace_root,
            openssl,
            private_key,
            public_key,
            watchdog,
            owner_user_id,
        }
    }

    // Creates the exact validated native configuration retained by this fixture.
    fn configuration(&self) -> ApplicationCoreBenchmarkConfiguration {
        ApplicationCoreBenchmarkConfiguration::new(
            self.worker.clone(),
            self.task_root.clone(),
            self.telemetry_root.clone(),
            self.evidence_root.clone(),
            self.signing_workspace_root.clone(),
            self.openssl.clone(),
            self.private_key.clone(),
            self.public_key.clone(),
            self.watchdog.clone(),
            self.owner_user_id,
            60_000,
            5_000,
        )
        .expect("configuration")
    }

    // Creates the exact shared managers and stores retained by this fixture.
    fn managers(&self) -> ApplicationCoreBenchmarkManagers {
        ApplicationCoreBenchmarkManagers::new(
            self.database.clone(),
            self.node.clone(),
            self.runtime.clone(),
            self.runtime_store.clone(),
            self.executions.clone(),
            self.placement.clone(),
            self.placement_store.clone(),
            self.credentials.clone(),
        )
    }

    // Creates the two explicit authorities with no default implementation.
    fn ports(&self) -> ApplicationCoreBenchmarkPorts {
        ApplicationCoreBenchmarkPorts::new(self.community.clone(), self.observations.clone())
    }
}

// Creates one stable active-main identity used only for durable composition.
fn local_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Benchmark Test").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("benchmark.local:9770").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(1))
            .expect("timestamps"),
    )
}

// Creates one owner-only directory beneath an isolated canonical root.
fn private_directory(root: &std::path::Path, name: &str) -> PathBuf {
    let path = root.join(name);
    fs::create_dir(&path).expect("private directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("directory mode");
    path
}

// Creates one inert owner executable used only for constructor metadata validation.
fn executable_file(root: &std::path::Path, name: &str) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, b"fixture").expect("executable file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable mode");
    path
}

// Creates one non-empty owner-only signing-key fixture.
fn private_file(root: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).expect("private file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    path
}

// Returns the ordinary entry count without following or filtering production-owned files.
fn entry_count(path: &std::path::Path) -> usize {
    fs::read_dir(path).expect("directory entries").count()
}

// Proves production composition retains one shared manager graph without invoking any provider.
#[test]
fn production_composition_shares_existing_owners_without_external_work() {
    let fixture = Fixture::new();
    let database_count = Arc::strong_count(&fixture.database);
    let node_count = Arc::strong_count(&fixture.node);
    let runtime_count = Arc::strong_count(&fixture.runtime);
    let runtime_store_count = Arc::strong_count(&fixture.runtime_store);
    let executions_count = Arc::strong_count(&fixture.executions);
    let placement_count = Arc::strong_count(&fixture.placement);
    let placement_store_count = Arc::strong_count(&fixture.placement_store);
    let credentials_count = Arc::strong_count(&fixture.credentials);
    let coordinator =
        compose_system_core_benchmark(fixture.configuration(), fixture.managers(), fixture.ports())
            .expect("production composition");

    assert_eq!(coordinator.active(), Ok(None));
    assert_eq!(fixture.counter.value(), 0);
    assert_eq!(Arc::strong_count(&fixture.database), database_count + 1);
    assert_eq!(Arc::strong_count(&fixture.node), node_count + 2);
    assert_eq!(Arc::strong_count(&fixture.runtime), runtime_count + 2);
    assert_eq!(
        Arc::strong_count(&fixture.runtime_store),
        runtime_store_count + 3
    );
    assert_eq!(Arc::strong_count(&fixture.executions), executions_count + 1);
    assert_eq!(Arc::strong_count(&fixture.placement), placement_count + 2);
    assert_eq!(
        Arc::strong_count(&fixture.placement_store),
        placement_store_count + 3
    );
    assert_eq!(
        Arc::strong_count(&fixture.credentials),
        credentials_count + 1
    );
    assert_eq!(entry_count(&fixture.task_root), 0);
    assert_eq!(entry_count(&fixture.telemetry_root), 0);
    assert_eq!(entry_count(&fixture.evidence_root), 0);
    assert_eq!(entry_count(&fixture.signing_workspace_root), 0);
}

// Proves unsafe evidence metadata fails during read-only preflight before journal or file mutation.
#[test]
fn native_preflight_rejects_unsafe_inputs_before_mutation() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.evidence_root, fs::Permissions::from_mode(0o755))
        .expect("unsafe evidence mode");
    let result =
        compose_system_core_benchmark(fixture.configuration(), fixture.managers(), fixture.ports());

    assert!(matches!(
        result,
        Err(CoreBenchmarkCompositionError::Benchmark(
            BenchmarkError::Provider { .. }
        ))
    ));
    assert_eq!(fixture.counter.value(), 0);
    let store = DatabaseBenchmarkStore::new(fixture.database.clone());
    assert_eq!(store.active(), Ok(None));
    assert_eq!(entry_count(&fixture.task_root), 0);
    assert_eq!(entry_count(&fixture.telemetry_root), 0);
    assert_eq!(entry_count(&fixture.evidence_root), 0);
    assert_eq!(entry_count(&fixture.signing_workspace_root), 0);
}

// Proves path aliasing and deadline overflow are rejected by the typed configuration boundary.
#[test]
fn configuration_rejects_aliased_ownership_and_unbounded_deadlines() {
    let fixture = Fixture::new();
    let aliased = ApplicationCoreBenchmarkConfiguration::new(
        fixture.worker.clone(),
        fixture.task_root.clone(),
        fixture.telemetry_root.clone(),
        fixture.task_root.clone(),
        fixture.signing_workspace_root.clone(),
        fixture.openssl.clone(),
        fixture.private_key.clone(),
        fixture.public_key.clone(),
        fixture.watchdog.clone(),
        fixture.owner_user_id,
        60_000,
        5_000,
    );
    let unbounded = ApplicationCoreBenchmarkConfiguration::new(
        fixture.worker,
        fixture.task_root,
        fixture.telemetry_root,
        fixture.evidence_root,
        fixture.signing_workspace_root,
        fixture.openssl,
        fixture.private_key,
        fixture.public_key,
        fixture.watchdog,
        fixture.owner_user_id,
        7 * 24 * 60 * 60 * 1000 + 1,
        5_000,
    );

    assert_eq!(
        aliased,
        Err(CoreBenchmarkCompositionError::InvalidConfiguration)
    );
    assert_eq!(
        unbounded,
        Err(CoreBenchmarkCompositionError::InvalidConfiguration)
    );
    assert_eq!(fixture.counter.value(), 0);
}
