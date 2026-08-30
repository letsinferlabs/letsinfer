// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::{
    BootId, ByteCount, CpuArchitecture, DisplayName, EntityTimestamps, HardwareObservation,
    HardwareObservationId, InstallationId, MachineId, Node, NodeAddress, NodeId, NodeIdentity,
    NodeRole, NodeState, OperatingSystem, PlatformIdentity, ProcessorObservation, UnixMilliseconds,
};
use li_database::{DatabaseClock, DatabaseConfiguration, DatabaseError, DatabaseManager};
use li_node_manager::{
    NodeConfiguration, NodeConfigurationError, NodeConfigurationFile,
    NodeConfigurationFileProvider, NodeConfigurationFileReference, NodeDaemon, NodeDaemonClock,
    NodeDaemonError, NodeHardwareObservationProvider, NodeManager, NodeManagerError,
    NodeOutboxDeliveryProvider, NodeOutboxEvent, NodeResident, NodeResidentError,
    NodeResidentListenerHandle, NodeResidentLocalListenerProvider,
    NodeResidentRemoteListenerProvider, NodeResidentRunControl, NodeResidentRunDecision,
    NodeResidentRunSignal, NodeResidentThreadHandle, NodeResidentThreadProvider,
    SystemNodeResidentThreadProvider,
};

// Supplies deterministic increasing database commit timestamps.
struct TestDatabaseClock(AtomicI64);

impl DatabaseClock for TestDatabaseClock {
    // Returns one unique commit timestamp.
    fn now_unix_milliseconds(&self) -> Result<i64, DatabaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

// Returns one coherent active local Node for an exact role.
fn local_node(role: NodeRole) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("Home AI").expect("name"),
        role,
        NodeState::Active,
        NodeAddress::parse("homeai.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
}

// Opens one isolated shared NodeManager for the supplied local role.
fn manager(directory: &tempfile::TempDir, role: NodeRole) -> Arc<NodeManager> {
    let database = Arc::new(
        DatabaseManager::open(
            DatabaseConfiguration::new(directory.path().join("core.sqlite3"))
                .with_busy_timeout(Duration::from_secs(1))
                .with_clock(Arc::new(TestDatabaseClock(AtomicI64::new(10_000)))),
        )
        .expect("database"),
    );
    Arc::new(
        NodeManager::open(database, local_node(role), "initialize-node")
            .expect("manager")
            .0,
    )
}

// Returns one minimal complete hardware observation for the local Node.
fn observation() -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&"4".repeat(32)).expect("observation"),
        NodeId::parse(&"1".repeat(32)).expect("node"),
        BootId::parse("boot-1").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA GB10").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("memory"),
        Vec::new(),
        Vec::new(),
        UnixMilliseconds::new(2_000),
    )
    .expect("observation")
}

// Counts every cadence observation while returning one stable valid snapshot.
struct CountingHardware {
    calls: AtomicUsize,
}

impl NodeHardwareObservationProvider for CountingHardware {
    // Records one cadence cycle and returns the same valid observation identity.
    fn observe(&self) -> Result<HardwareObservation, NodeManagerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(observation())
    }
}

// Acknowledges every durable outbox event without retaining its contents.
struct Delivery;

impl NodeOutboxDeliveryProvider for Delivery {
    // Accepts one idempotent durable event delivery.
    fn deliver(&self, _event: &NodeOutboxEvent) -> Result<(), NodeDaemonError> {
        Ok(())
    }
}

// Supplies one deterministic acknowledgement time after every fixture event.
struct DaemonClock;

impl NodeDaemonClock for DaemonClock {
    // Returns one fixed valid acknowledgement time.
    fn now(&self) -> Result<UnixMilliseconds, NodeDaemonError> {
        Ok(UnixMilliseconds::new(20_000))
    }
}

// Creates one NodeDaemon and retains its hardware cadence counter.
fn daemon(manager: Arc<NodeManager>) -> (Arc<NodeDaemon>, Arc<CountingHardware>) {
    let hardware = Arc::new(CountingHardware {
        calls: AtomicUsize::new(0),
    });
    (
        Arc::new(NodeDaemon::new(
            manager,
            hardware.clone(),
            Arc::new(Delivery),
            Arc::new(DaemonClock),
        )),
        hardware,
    )
}

// Returns one complete closed configuration document for resident tests.
fn configuration_bytes() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": {"name": "li_node_configuration", "version": 4},
        "runtime": {"database_file": "/var/lib/letsinfer/core.sqlite3"},
        "core_update": {
            "release_platform": "macos_arm64", "letsinfer_home": "/var/lib/letsinfer",
            "home_directory": "/Users/test", "setup_state_directory": "/var/lib/letsinfer/setup",
            "configuration_root": "/etc/letsinfer", "curl_command": "/usr/bin/curl",
            "ssh_keygen_command": "/usr/bin/ssh-keygen",
            "allowed_signers_file": "/var/lib/letsinfer/trust/release-allowed-signers",
            "supervisor_command": "/bin/launchctl", "readiness_timeout_milliseconds": 30000,
            "readiness_poll_milliseconds": 100, "stable_readiness_observations": 2
        },
        "model": {
            "catalog_source": "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json",
            "catalog_cache_root": "/var/lib/letsinfer/catalog-cache",
            "catalog_hydration_root": "/var/lib/letsinfer/catalog-hydration",
            "http_workspace_root": "/var/lib/letsinfer/http-workspace",
            "installation_root": "/var/lib/letsinfer/runtimes",
            "runtime_cache_root": "/var/lib/letsinfer/cache",
            "curl_command": "/usr/bin/curl",
            "docker_command": "/usr/bin/false",
            "command_working_directory": "/var/lib/letsinfer/command-workspace",
            "placement_material_root": "/var/lib/letsinfer/placement-material",
            "placement_secret_root": "/var/lib/letsinfer/placement-secrets",
            "placement_tls_workspace_root": "/var/lib/letsinfer/placement-tls-staging",
            "first_port": 18000,
            "port_count": 32,
            "endpoint_timeout_milliseconds": 1000,
            "maximum_hardware_age_milliseconds": 60000,
            "group_id": 20,
            "launch_agents_root": "/Users/test/Library/LaunchAgents",
            "launchctl_command": "/bin/launchctl"
        },
        "benchmark": null,
        "pairing": {
            "setup_secret_file": "/var/lib/letsinfer/secrets/pairing_setup.key", "operating_system": "macos",
            "discovery_command": "/usr/bin/dns-sd", "openssl_command": "/usr/bin/openssl",
            "trust_workspace": "/var/lib/letsinfer/trust/pairing_trust_staging",
            "site_private_key_file": "/var/lib/letsinfer/trust/site.key", "site_public_key_file": "/var/lib/letsinfer/trust/site.pub",
            "site_ca_certificate_file": "/var/lib/letsinfer/trust/site-ca.crt", "local_control_certificate_file": "/var/lib/letsinfer/trust/node.crt",
            "public_key_sha256": "11".repeat(32), "certificate_sha256": "22".repeat(32)
        },
        "hardware": {
            "operating_system": "macos",
            "architecture": "arm64",
            "sysctl_command": "/usr/sbin/sysctl",
            "metal_probe_command": "/usr/local/libexec/li_metal_probe"
        },
        "placement_safety": {"operating_system": "macos"},
        "daemon": {"cadence_milliseconds": 100},
        "private_api": {
            "local": {
                "socket_path": "/tmp/letsinfer-node.sock",
                "maximum_workers": 4,
                "read_timeout_milliseconds": 1000,
                "write_timeout_milliseconds": 1000,
                "accept_poll_interval_milliseconds": 10
            },
            "remote": {
                "bind_address": "127.0.0.1:9770",
                "maximum_workers": 4,
                "accept_poll_interval_milliseconds": 10,
                "handshake_timeout_milliseconds": 1000,
                "read_timeout_milliseconds": 1000,
                "write_timeout_milliseconds": 1000,
                "server_certificate_file": "/tmp/node.crt",
                "server_private_key_file": "/tmp/node.key",
                "client_ca_file": "/tmp/main-ca.crt"
            }
        }
    }))
    .expect("configuration")
}

// Returns one owner-only in-memory configuration observation.
struct ConfigurationProvider;

impl NodeConfigurationFileProvider for ConfigurationProvider {
    // Returns one exact descriptor-shaped configuration observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<NodeConfigurationFile, NodeConfigurationError> {
        Ok(NodeConfigurationFile::new(
            501,
            0o600,
            1,
            true,
            configuration_bytes(),
        ))
    }
}

// Loads the same validated resident configuration used by every lifecycle scenario.
fn configuration() -> NodeConfiguration {
    NodeConfiguration::load(
        &NodeConfigurationFileReference::new("/etc/letsinfer/node.json".into(), 501)
            .expect("reference"),
        &ConfigurationProvider,
    )
    .expect("configuration")
}

// Retains listener startup, health, stop behavior, and exact lifecycle order.
struct MockListenerState {
    kind: &'static str,
    start_error: Mutex<Option<NodeResidentError>>,
    running_after_start: AtomicBool,
    stop_error: Mutex<Option<NodeResidentError>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl MockListenerState {
    // Creates one healthy listener state for a fixed local or remote role.
    fn healthy(kind: &'static str, events: Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Self {
            kind,
            start_error: Mutex::new(None),
            running_after_start: AtomicBool::new(true),
            stop_error: Mutex::new(None),
            events,
        })
    }

    // Starts one deterministic handle or returns the injected start failure.
    fn start(self: &Arc<Self>) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError> {
        self.events
            .lock()
            .expect("events")
            .push(format!("{}_start", self.kind));
        if let Some(error) = *self.start_error.lock().expect("start error") {
            return Err(error);
        }
        Ok(Box::new(MockListenerHandle {
            state: self.clone(),
            running: self.running_after_start.load(Ordering::SeqCst),
        }))
    }
}

// Adapts one retained mock state to the local listener provider contract.
struct MockLocalListener(Arc<MockListenerState>);

impl NodeResidentLocalListenerProvider for MockLocalListener {
    // Starts one deterministic local listener handle.
    fn start_local_listener(
        &self,
    ) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError> {
        self.0.start()
    }
}

// Adapts one retained mock state to the remote listener provider contract.
struct MockRemoteListener(Arc<MockListenerState>);

impl NodeResidentRemoteListenerProvider for MockRemoteListener {
    // Starts one deterministic remote listener handle.
    fn start_remote_listener(
        &self,
    ) -> Result<Box<dyn NodeResidentListenerHandle>, NodeResidentError> {
        self.0.start()
    }
}

// Owns one deterministic mock listener until its stop boundary.
struct MockListenerHandle {
    state: Arc<MockListenerState>,
    running: bool,
}

impl NodeResidentListenerHandle for MockListenerHandle {
    // Returns the retained deterministic health state.
    fn is_running(&self) -> bool {
        self.running
    }

    // Records one exact stop and returns its optional injected failure.
    fn stop(&mut self) -> Result<(), NodeResidentError> {
        self.running = false;
        self.state
            .events
            .lock()
            .expect("events")
            .push(format!("{}_stop", self.state.kind));
        self.state
            .stop_error
            .lock()
            .expect("stop error")
            .map_or(Ok(()), Err)
    }
}

// Rejects the resident thread start before executing its task.
struct FailingThreadProvider;

impl NodeResidentThreadProvider for FailingThreadProvider {
    // Returns the exact injected thread-start failure.
    fn spawn(
        &self,
        _task: Box<dyn FnOnce() -> Result<(), NodeResidentError> + Send>,
    ) -> Result<Box<dyn NodeResidentThreadHandle>, NodeResidentError> {
        Err(NodeResidentError::DaemonThreadStartFailed)
    }
}

// Returns queued cadence decisions or one injected run-control failure.
struct SequenceRunControl {
    decisions: Mutex<VecDeque<Result<NodeResidentRunDecision, NodeResidentError>>>,
    stopped: AtomicBool,
}

impl SequenceRunControl {
    // Creates one deterministic decision sequence.
    fn new(decisions: Vec<Result<NodeResidentRunDecision, NodeResidentError>>) -> Self {
        Self {
            decisions: Mutex::new(decisions.into()),
            stopped: AtomicBool::new(false),
        }
    }
}

impl NodeResidentRunControl for SequenceRunControl {
    // Returns the retained explicit stop state.
    fn is_stop_requested(&self) -> Result<bool, NodeResidentError> {
        Ok(self.stopped.load(Ordering::SeqCst))
    }

    // Returns the next queued decision without waiting on wall time.
    fn wait(&self, _cadence: Duration) -> Result<NodeResidentRunDecision, NodeResidentError> {
        self.decisions
            .lock()
            .expect("decisions")
            .pop_front()
            .unwrap_or(Ok(NodeResidentRunDecision::Stop))
    }

    // Records one deterministic explicit stop request.
    fn request_stop(&self) -> Result<(), NodeResidentError> {
        self.stopped.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// Creates one resident around retained listener states and injected run control.
fn resident(
    daemon: Arc<NodeDaemon>,
    local: Arc<MockListenerState>,
    remote: Arc<MockListenerState>,
    run_control: Arc<dyn NodeResidentRunControl>,
    threads: Arc<dyn NodeResidentThreadProvider>,
) -> NodeResident {
    NodeResident::new(
        &configuration(),
        daemon,
        Arc::new(MockLocalListener(local)),
        Arc::new(MockRemoteListener(remote)),
        run_control,
        threads,
    )
}

// Waits for one deterministic asynchronous condition without an unbounded sleep.
fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::yield_now();
    }
}

// Runs both listeners and immediate daemon cadence for main and child roles, then stops cleanly.
#[test]
fn resident_runs_and_shuts_down_cleanly_for_both_node_roles() {
    for role in [NodeRole::Main, NodeRole::Child] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (daemon, hardware) = daemon(manager(&directory, role));
        let events = Arc::new(Mutex::new(Vec::new()));
        let local = MockListenerState::healthy("local", events.clone());
        let remote = MockListenerState::healthy("remote", events.clone());
        let signal = Arc::new(NodeResidentRunSignal::new());
        let resident = resident(
            daemon,
            local,
            remote,
            signal.clone(),
            Arc::new(SystemNodeResidentThreadProvider),
        );
        let mut handle = resident.start().expect("start");
        assert_eq!(
            resident.start().err().expect("overlap"),
            NodeResidentError::AlreadyRunning
        );
        wait_until(|| hardware.calls.load(Ordering::SeqCst) >= 1);
        signal.signal_stop().expect("signal");
        handle.wait().expect("wait");
        assert!(!handle.is_running());
        assert_eq!(
            *events.lock().expect("events"),
            ["local_start", "remote_start", "remote_stop", "local_stop"]
        );
    }
}

// Reconstructs a second resident over the same durable manager after the first stops.
#[test]
fn resident_restarts_from_committed_node_state_without_listener_overlap() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let manager = manager(&directory, NodeRole::Main);
    for _ in 0..2 {
        let (daemon, hardware) = daemon(manager.clone());
        let events = Arc::new(Mutex::new(Vec::new()));
        let signal = Arc::new(NodeResidentRunSignal::new());
        let resident = resident(
            daemon,
            MockListenerState::healthy("local", events.clone()),
            MockListenerState::healthy("remote", events),
            signal.clone(),
            Arc::new(SystemNodeResidentThreadProvider),
        );
        let mut handle = resident.start().expect("start");
        wait_until(|| hardware.calls.load(Ordering::SeqCst) >= 1);
        signal.signal_stop().expect("signal");
        handle.wait().expect("wait");
    }
    assert_eq!(manager.local_node().expect("local").role(), NodeRole::Main);
    assert!(manager
        .hardware_observation(manager.local_node_id())
        .expect("hardware")
        .is_some());
}

// Rolls back local, remote, and thread partial starts in exact reverse acquisition order.
#[test]
fn resident_rolls_back_every_partial_start_boundary() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (daemon, _) = daemon(manager(&directory, NodeRole::Main));
    let events = Arc::new(Mutex::new(Vec::new()));
    let local = MockListenerState::healthy("local", events.clone());
    let remote = MockListenerState::healthy("remote", events.clone());
    *remote.start_error.lock().expect("start error") =
        Some(NodeResidentError::RemoteListenerStartFailed);
    let remote_failure_resident = resident(
        daemon.clone(),
        local,
        remote,
        Arc::new(SequenceRunControl::new(Vec::new())),
        Arc::new(SystemNodeResidentThreadProvider),
    );
    assert_eq!(
        remote_failure_resident
            .start()
            .err()
            .expect("remote failure"),
        NodeResidentError::RemoteListenerStartFailed
    );
    assert_eq!(
        *events.lock().expect("events"),
        ["local_start", "remote_start", "local_stop"]
    );

    let events = Arc::new(Mutex::new(Vec::new()));
    let thread_failure_resident = resident(
        daemon,
        MockListenerState::healthy("local", events.clone()),
        MockListenerState::healthy("remote", events.clone()),
        Arc::new(SequenceRunControl::new(Vec::new())),
        Arc::new(FailingThreadProvider),
    );
    assert_eq!(
        thread_failure_resident
            .start()
            .err()
            .expect("thread failure"),
        NodeResidentError::DaemonThreadStartFailed
    );
    assert_eq!(
        *events.lock().expect("events"),
        ["local_start", "remote_start", "remote_stop", "local_stop"]
    );
}

// Stops both listeners after a resident-loop failure and preserves the first cleanup failure.
#[test]
fn resident_propagates_run_control_and_shutdown_failures_after_complete_cleanup() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (daemon, _) = daemon(manager(&directory, NodeRole::Main));
    let events = Arc::new(Mutex::new(Vec::new()));
    let local = MockListenerState::healthy("local", events.clone());
    let remote = MockListenerState::healthy("remote", events.clone());
    *remote.stop_error.lock().expect("stop error") =
        Some(NodeResidentError::RemoteListenerStopFailed);
    *local.stop_error.lock().expect("stop error") =
        Some(NodeResidentError::LocalListenerStopFailed);
    let resident = resident(
        daemon,
        local,
        remote,
        Arc::new(SequenceRunControl::new(vec![Err(
            NodeResidentError::RunControlFailed,
        )])),
        Arc::new(SystemNodeResidentThreadProvider),
    );
    let mut handle = resident.start().expect("start");
    assert_eq!(handle.wait(), Err(NodeResidentError::RunControlFailed));
    assert_eq!(
        *events.lock().expect("events"),
        ["local_start", "remote_start", "remote_stop", "local_stop"]
    );
}
