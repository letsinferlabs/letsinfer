// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, hard_link};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner, CoreNativeServiceSupervisor,
    CoreNativeServiceWaiter, CoreProcessPlatform, CoreResidentProcess, CoreResidentProcessCommand,
    CoreServiceCutoverFile, CoreServiceCutoverFileIo, CoreServiceCutoverNativeHost,
    CoreServiceCutoverNativeSnapshot, CoreServiceCutoverPhase, CoreServiceCutoverReceipt,
    CoreServiceCutoverRecord, CoreServiceCutoverStore, CoreServiceDefinition, CoreServiceSetup,
    CoreServiceSetupError, CoreServiceSetupHealthProvider, CoreServiceSetupObservation,
    CoreServiceSetupPreflight, CoreServiceSetupWaiter, DurableCoreServiceCutoverProvider,
    SystemCoreServiceCutoverFileIo, SystemCoreServiceCutoverNativeHost,
};
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateError, CoreUpdateNodeRole, CoreUpdateServiceContext,
    CoreUpdateServicePlatform, CoreUpdateServiceState, CoreVersion,
};

const LINUX_IDENTITIES: [&str; 3] = [
    "li_gateway.service",
    "li_node.service",
    "li_watchdog.service",
];

const MACOS_IDENTITIES: [&str; 2] = ["ai.letsinfer.gateway", "ai.letsinfer.node"];

// Carries one closed native service fixture before conversion to supervisor output.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ServiceState {
    file: Option<CoreServiceCutoverFile>,
    enablement: &'static str,
    activity: &'static str,
    disabled: Option<bool>,
}

// Stores one exact shell-free command invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandCall {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    maximum_stdout_bytes: usize,
}

// Returns queued native results and retains exact argv for ordering assertions.
#[derive(Default)]
struct CommandRunnerMock {
    outputs: Mutex<VecDeque<Result<CoreNativeServiceCommandOutput, CoreUpdateError>>>,
    calls: Mutex<Vec<CommandCall>>,
}

impl CommandRunnerMock {
    // Appends one result with exact standard output.
    fn output(&self, status: i32, stdout: &str) {
        self.outputs
            .lock()
            .expect("outputs")
            .push_back(Ok(CoreNativeServiceCommandOutput::new(
                status,
                stdout.as_bytes().to_vec(),
            )));
    }

    // Appends one result with exact standard error.
    fn diagnostic(&self, status: i32, stderr: &str) {
        self.outputs.lock().expect("outputs").push_back(Ok(
            CoreNativeServiceCommandOutput::new_with_stderr(
                status,
                Vec::new(),
                stderr.as_bytes().to_vec(),
            ),
        ));
    }

    // Appends the requested number of successful mutation results.
    fn successes(&self, count: usize) {
        for _ in 0..count {
            self.output(0, "");
        }
    }

    // Returns and clears every captured command.
    fn take_calls(&self) -> Vec<CommandCall> {
        std::mem::take(&mut *self.calls.lock().expect("calls"))
    }
}

impl CoreNativeServiceCommandRunner for CommandRunnerMock {
    // Captures one invocation and returns the next deterministic result.
    fn run(
        &self,
        executable: &Path,
        arguments: &[String],
        timeout: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<CoreNativeServiceCommandOutput, CoreUpdateError> {
        self.calls.lock().expect("calls").push(CommandCall {
            executable: executable.to_path_buf(),
            arguments: arguments.to_vec(),
            timeout,
            maximum_stdout_bytes,
        });
        self.outputs
            .lock()
            .expect("outputs")
            .pop_front()
            .expect("queued native output")
    }
}

// Captures exact launchd retry intervals and supports one injected wait failure.
#[derive(Default)]
struct WaiterMock {
    durations: Mutex<Vec<Duration>>,
    fail: Mutex<bool>,
}

impl CoreNativeServiceWaiter for WaiterMock {
    // Records one retry interval or returns one redacted injected failure.
    fn wait(&self, duration: Duration) -> Result<(), CoreUpdateError> {
        self.durations.lock().expect("durations").push(duration);
        if *self.fail.lock().expect("fail") {
            return Err(CoreUpdateError::provider(
                "test launchd wait",
                "injected failure",
            ));
        }
        Ok(())
    }
}

// Identifies one file operation that must fail exactly once.
#[derive(Clone)]
struct FileFailure {
    operation: &'static str,
    filename: String,
}

// Stores exact native files while exposing deterministic partial-I/O failures.
#[derive(Default)]
struct FileIoMock {
    files: Mutex<BTreeMap<PathBuf, CoreServiceCutoverFile>>,
    mutations: Mutex<Vec<String>>,
    failure: Mutex<Option<FileFailure>>,
}

impl FileIoMock {
    // Inserts one exact native file without recording a mutation.
    fn insert(&self, path: PathBuf, file: CoreServiceCutoverFile) {
        self.files.lock().expect("files").insert(path, file);
    }

    // Removes every current fixture without recording lifecycle mutation.
    fn clear(&self) {
        self.files.lock().expect("files").clear();
    }

    // Arms one exact replace or remove failure for the next matching operation.
    fn fail_once(&self, operation: &'static str, filename: &str) {
        *self.failure.lock().expect("failure") = Some(FileFailure {
            operation,
            filename: filename.to_string(),
        });
    }

    // Returns whether one file operation consumes the injected failure.
    fn should_fail(&self, operation: &'static str, path: &Path) -> bool {
        let mut failure = self.failure.lock().expect("failure");
        let matches = failure.as_ref().is_some_and(|failure| {
            failure.operation == operation
                && path.file_name().and_then(|value| value.to_str())
                    == Some(failure.filename.as_str())
        });
        if matches {
            *failure = None;
        }
        matches
    }

    // Returns and clears the exact mutation history.
    fn take_mutations(&self) -> Vec<String> {
        std::mem::take(&mut *self.mutations.lock().expect("mutations"))
    }
}

impl CoreServiceCutoverFileIo for FileIoMock {
    // Accepts the already-fixed mock service root.
    fn validate_root(
        &self,
        _root: &Path,
        _owner_user_id: u32,
    ) -> Result<(), li_core_application::CoreServiceSetupError> {
        Ok(())
    }

    // Returns one exact optional in-memory definition.
    fn read(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<Option<CoreServiceCutoverFile>, li_core_application::CoreServiceSetupError> {
        Ok(self.files.lock().expect("files").get(path).cloned())
    }

    // Replaces one exact in-memory definition or fails before mutation.
    fn replace(
        &self,
        path: &Path,
        file: &CoreServiceCutoverFile,
        _owner_user_id: u32,
    ) -> Result<(), li_core_application::CoreServiceSetupError> {
        if self.should_fail("replace", path) {
            return Err(li_core_application::CoreServiceSetupError::provider(
                "test file I/O",
                "injected replace failure",
            ));
        }
        self.mutations.lock().expect("mutations").push(format!(
            "replace:{}:{:o}",
            path.display(),
            file.mode()
        ));
        self.files
            .lock()
            .expect("files")
            .insert(path.to_path_buf(), file.clone());
        Ok(())
    }

    // Removes one optional in-memory definition or fails before mutation.
    fn remove(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, li_core_application::CoreServiceSetupError> {
        if self.should_fail("remove", path) {
            return Err(li_core_application::CoreServiceSetupError::provider(
                "test file I/O",
                "injected remove failure",
            ));
        }
        self.mutations
            .lock()
            .expect("mutations")
            .push(format!("remove:{}", path.display()));
        Ok(self.files.lock().expect("files").remove(path).is_some())
    }
}

// Stores one exact cutover record for a production-provider rollback composition.
#[derive(Default)]
struct ExactCutoverStore {
    record: Mutex<Option<CoreServiceCutoverRecord>>,
}

impl CoreServiceCutoverStore for ExactCutoverStore {
    // Returns the complete current in-memory record.
    fn read(&self) -> Result<Option<CoreServiceCutoverRecord>, CoreServiceSetupError> {
        Ok(self.record.lock().expect("record").clone())
    }

    // Creates one record once or returns its exact existing value.
    fn create(
        &self,
        record: CoreServiceCutoverRecord,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        let mut current = self.record.lock().expect("record");
        if let Some(existing) = current.as_ref() {
            return Ok(existing.clone());
        }
        *current = Some(record.clone());
        Ok(record)
    }

    // Applies one exact legal phase transition for the bound receipt.
    fn transition(
        &self,
        receipt: &CoreServiceCutoverReceipt,
        expected: CoreServiceCutoverPhase,
        next: CoreServiceCutoverPhase,
    ) -> Result<CoreServiceCutoverRecord, CoreServiceSetupError> {
        let mut current = self.record.lock().expect("record");
        let record = current
            .as_ref()
            .ok_or(CoreServiceSetupError::InvalidContract {
                reason: "test cutover record is unavailable",
            })?;
        assert_eq!(record.receipt_id(), receipt.receipt_id());
        let transitioned = record.transitioned(expected, next)?;
        *current = Some(transitioned.clone());
        Ok(transitioned)
    }

    // Removes only the record owned by the exact durable receipt.
    fn remove(&self, receipt: &CoreServiceCutoverReceipt) -> Result<(), CoreServiceSetupError> {
        let mut current = self.record.lock().expect("record");
        assert_eq!(
            current.as_ref().map(CoreServiceCutoverRecord::receipt_id),
            Some(receipt.receipt_id())
        );
        *current = None;
        Ok(())
    }
}

// Installs exact Rust plist bytes while making only Gateway native readiness fail.
struct GatewayFailureSupervisor {
    io: Arc<FileIoMock>,
}

impl CoreNativeServiceSupervisor for GatewayFailureSupervisor {
    // Rejects direct observation because setup owns only installation and readiness.
    fn observe(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
    ) -> Result<CoreUpdateServiceState, CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test supervisor",
            "unexpected observation",
        ))
    }

    // Replaces one resident plist with the exact generated Rust definition.
    fn install(
        &self,
        definition: &CoreServiceDefinition,
        active: bool,
    ) -> Result<(), CoreUpdateError> {
        assert!(active);
        self.io.insert(
            macos_path(definition.service_identity()),
            CoreServiceCutoverFile::new(definition.bytes().to_vec(), definition.mode())
                .expect("generated definition"),
        );
        Ok(())
    }

    // Keeps Node ready while forcing the exact Gateway rollback boundary.
    fn is_ready(
        &self,
        platform: CoreProcessPlatform,
        process: CoreResidentProcess,
        definition: Option<&CoreServiceDefinition>,
        active: bool,
    ) -> Result<bool, CoreUpdateError> {
        assert_eq!(platform, CoreProcessPlatform::Macos);
        assert_eq!(
            definition.map(CoreServiceDefinition::process),
            Some(process)
        );
        assert!(active);
        Ok(process != CoreResidentProcess::Gateway)
    }

    // Rejects direct restoration because the durable cutover owns whole-set rollback.
    fn restore(
        &self,
        _platform: CoreProcessPlatform,
        _process: CoreResidentProcess,
        _definition: Option<&CoreServiceDefinition>,
        _active: bool,
    ) -> Result<(), CoreUpdateError> {
        Err(CoreUpdateError::provider(
            "test supervisor",
            "unexpected direct restoration",
        ))
    }
}

// Accepts the already-bounded fixture contract before native snapshot ownership begins.
struct AcceptingPreflight;

impl CoreServiceSetupPreflight for AcceptingPreflight {
    // Accepts one exact macOS setup request without native mutation.
    fn verify(
        &self,
        _context: CoreUpdateServiceContext,
        _installation: &CoreInstallation,
        _commands: &[CoreResidentProcessCommand],
    ) -> Result<(), CoreServiceSetupError> {
        Ok(())
    }
}

// Keeps semantic health ready so the test isolates native Gateway readiness.
struct ReadyMacosHealth;

impl CoreServiceSetupHealthProvider for ReadyMacosHealth {
    // Reports every resident semantic endpoint ready.
    fn resident_health(
        &self,
        _context: CoreUpdateServiceContext,
        _process: CoreResidentProcess,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(CoreServiceSetupObservation::Ready)
    }

    // Uses the explicit macOS unsupported memory-envelope contract.
    fn memory_envelope(
        &self,
        _context: CoreUpdateServiceContext,
        _definition: &CoreServiceDefinition,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        Ok(CoreServiceSetupObservation::Unsupported)
    }
}

// Advances one failed readiness retry directly to the fixed setup deadline.
#[derive(Default)]
struct DeadlineWaiter {
    now: Mutex<Duration>,
}

impl CoreServiceSetupWaiter for DeadlineWaiter {
    // Returns the exact deterministic monotonic fixture time.
    fn now(&self) -> Result<Duration, CoreServiceSetupError> {
        Ok(*self.now.lock().expect("time"))
    }

    // Advances to the production deadline after one bounded retry request.
    fn wait(&self, duration: Duration) -> Result<(), CoreServiceSetupError> {
        assert_eq!(duration, Duration::from_millis(250));
        *self.now.lock().expect("time") = Duration::from_secs(90);
        Ok(())
    }
}

// Creates one exact bounded service-definition fixture.
fn file(value: &str, mode: u32) -> CoreServiceCutoverFile {
    CoreServiceCutoverFile::new(value.as_bytes().to_vec(), mode).expect("service file")
}

// Returns the exact Linux service path beneath the mock home.
fn linux_path(identity: &str) -> PathBuf {
    PathBuf::from("/home/test/.config/systemd/user").join(identity)
}

// Returns the exact macOS service path beneath the mock home.
fn macos_path(identity: &str) -> PathBuf {
    PathBuf::from("/Users/test/Library/LaunchAgents").join(format!("{identity}.plist"))
}

// Creates one Linux host with fully injected native capabilities.
fn linux_host() -> (
    SystemCoreServiceCutoverNativeHost,
    Arc<CommandRunnerMock>,
    Arc<FileIoMock>,
) {
    let runner = Arc::new(CommandRunnerMock::default());
    let io = Arc::new(FileIoMock::default());
    let host = SystemCoreServiceCutoverNativeHost::new(
        CoreUpdateServicePlatform::Linux,
        PathBuf::from("/home/test"),
        1000,
        PathBuf::from("/usr/bin/systemctl"),
        runner.clone(),
        io.clone(),
    )
    .expect("Linux host");
    (host, runner, io)
}

// Creates one macOS host with an observable launchd retry waiter.
fn macos_host() -> (
    SystemCoreServiceCutoverNativeHost,
    Arc<CommandRunnerMock>,
    Arc<FileIoMock>,
    Arc<WaiterMock>,
) {
    let runner = Arc::new(CommandRunnerMock::default());
    let io = Arc::new(FileIoMock::default());
    let waiter = Arc::new(WaiterMock::default());
    let host = SystemCoreServiceCutoverNativeHost::new_with_waiter(
        CoreUpdateServicePlatform::Macos,
        PathBuf::from("/Users/test"),
        501,
        PathBuf::from("/bin/launchctl"),
        runner.clone(),
        io.clone(),
        waiter.clone(),
    )
    .expect("macOS host");
    (host, runner, io, waiter)
}

// Returns one explicit platform/role snapshot context.
fn context(platform: CoreUpdateServicePlatform) -> CoreUpdateServiceContext {
    CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main)
}

// Returns a Linux fixture covering every supported enablement and activity state.
fn mixed_linux_states() -> Vec<ServiceState> {
    vec![
        ServiceState {
            file: Some(file("Rust gateway", 0o644)),
            enablement: "enabled",
            activity: "active",
            disabled: None,
        },
        ServiceState {
            file: Some(file("Rust node", 0o600)),
            enablement: "disabled",
            activity: "failed",
            disabled: None,
        },
        ServiceState {
            file: Some(file("Rust watchdog", 0o644)),
            enablement: "static",
            activity: "inactive",
            disabled: None,
        },
    ]
}

// Returns an entirely absent Linux inventory after successful retirement.
fn absent_linux_states() -> Vec<ServiceState> {
    LINUX_IDENTITIES
        .iter()
        .map(|_| ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: None,
        })
        .collect()
}

// Installs the exact file projection of one Linux state vector into mock I/O.
fn install_linux_files(io: &FileIoMock, states: &[ServiceState]) {
    io.clear();
    for (identity, state) in LINUX_IDENTITIES.iter().zip(states) {
        if let Some(file) = &state.file {
            io.insert(linux_path(identity), file.clone());
        }
    }
}

// Queues exact `is-enabled` and `is-active` output for one Linux inventory.
fn queue_linux_states(runner: &CommandRunnerMock, states: &[ServiceState]) {
    assert_eq!(states.len(), LINUX_IDENTITIES.len());
    for state in states {
        match state.enablement {
            "enabled" => runner.output(0, "enabled\n"),
            "disabled" => runner.output(1, "disabled\n"),
            "static" => runner.output(0, "static\n"),
            "absent" => runner.output(4, "not-found\n"),
            value => panic!("unsupported test enablement {value}"),
        }
        match state.activity {
            "active" => runner.output(0, "active\n"),
            "inactive" => runner.output(3, "inactive\n"),
            "failed" => runner.output(3, "failed\n"),
            value => panic!("unsupported test activity {value}"),
        }
    }
}

// Derives one non-active Linux inventory from the files left after partial mutation.
fn linux_states_from_files(io: &FileIoMock) -> Vec<ServiceState> {
    let files = io.files.lock().expect("files");
    LINUX_IDENTITIES
        .iter()
        .map(|identity| {
            let file = files.get(&linux_path(identity)).cloned();
            ServiceState {
                enablement: if file.is_some() { "disabled" } else { "absent" },
                file,
                activity: "inactive",
                disabled: None,
            }
        })
        .collect()
}

// Installs the exact file projection of one macOS state vector into mock I/O.
fn install_macos_files(io: &FileIoMock, states: &[ServiceState]) {
    io.clear();
    for (identity, state) in MACOS_IDENTITIES.iter().zip(states) {
        if let Some(file) = &state.file {
            io.insert(macos_path(identity), file.clone());
        }
    }
}

// Queues exact `launchctl print` output for one macOS inventory.
fn queue_macos_states(runner: &CommandRunnerMock, states: &[ServiceState]) {
    assert_eq!(states.len(), MACOS_IDENTITIES.len());
    queue_macos_disabled(runner, states);
    for state in states {
        match state.enablement {
            "loaded" if state.activity == "active" => {
                runner.output(0, "service = {\n\tstate = running\n}\n")
            }
            "loaded" => runner.output(0, "service = {\n\tstate = waiting\n}\n"),
            "unloaded" | "absent" => runner.output(113, ""),
            value => panic!("unsupported test launchd state {value}"),
        }
    }
}

// Queues one coherent GUI-domain disabled map for every fixed macOS identity.
fn queue_macos_disabled(runner: &CommandRunnerMock, states: &[ServiceState]) {
    assert_eq!(states.len(), MACOS_IDENTITIES.len());
    let mut disabled = String::from("disabled services = {\n");
    for (identity, state) in MACOS_IDENTITIES.iter().zip(states) {
        disabled.push_str(&format!(
            "\t\"{identity}\" => {}\n",
            if state.disabled.expect("macOS disabled state") {
                "disabled"
            } else {
                "enabled"
            }
        ));
    }
    disabled.push_str("}\n");
    runner.output(0, &disabled);
}

// Returns the first exact command position for one ordering assertion.
fn command_position(calls: &[CommandCall], arguments: &[&str]) -> usize {
    calls
        .iter()
        .position(|call| {
            call.arguments
                .iter()
                .map(String::as_str)
                .eq(arguments.iter().copied())
        })
        .expect("exact command")
}

// Decodes one native snapshot into its public JSON representation for assertions.
fn snapshot_json(snapshot: &CoreServiceCutoverNativeSnapshot) -> serde_json::Value {
    serde_json::from_slice(snapshot.bytes()).expect("snapshot JSON")
}

// Creates one new content-addressed snapshot from a mutated JSON value.
fn mutated_snapshot(value: &serde_json::Value) -> CoreServiceCutoverNativeSnapshot {
    CoreServiceCutoverNativeSnapshot::new(serde_json::to_vec(value).expect("mutated JSON"))
        .expect("mutated snapshot")
}

// Captures every supported Linux state with exact ordered files, modes, and per-file identities.
#[test]
fn linux_snapshot_preserves_the_closed_exact_native_contract() {
    let (host, runner, io) = linux_host();
    let states = mixed_linux_states();
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    let value = snapshot_json(&snapshot);
    assert_eq!(value["schema"]["name"], "li_core_native_service_snapshot");
    assert_eq!(value["schema"]["version"], 1);
    assert_eq!(value["platform"], "linux");
    let services = value["services"].as_array().expect("services");
    assert_eq!(services.len(), LINUX_IDENTITIES.len());
    assert_eq!(
        services
            .iter()
            .map(|service| service["identity"].as_str().expect("identity"))
            .collect::<Vec<_>>(),
        LINUX_IDENTITIES
    );
    assert_eq!(services[0]["definition"]["mode"], 0o644);
    assert_eq!(services[1]["definition"]["mode"], 0o600);
    assert_eq!(
        services[1]["definition"]["sha256"]
            .as_str()
            .expect("SHA-256")
            .len(),
        64
    );
    assert!(io.take_mutations().is_empty());
    assert_eq!(runner.take_calls().len(), LINUX_IDENTITIES.len() * 2);

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/core/li_core_native_service_snapshot_v1.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(schema_path).expect("schema bytes")).expect("schema JSON");
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        value["schema"]["name"]
    );
}

// Retires active, failed, enabled, disabled, static, and absent Linux state idempotently.
#[test]
fn linux_retirement_is_complete_ordered_and_idempotent() {
    let (host, runner, io) = linux_host();
    let states = mixed_linux_states();
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    runner.take_calls();

    queue_linux_states(&runner, &states);
    runner.successes(4);
    host.retire(&snapshot).expect("first retirement");
    assert!(io.files.lock().expect("files").is_empty());
    let calls = runner.take_calls();
    assert_eq!(calls.len(), LINUX_IDENTITIES.len() * 2 + 4);
    assert!(calls
        .iter()
        .any(|call| call.arguments == ["--user", "stop", "li_gateway.service"]));
    let reset_calls = calls
        .iter()
        .filter(|call| {
            call.arguments
                .get(1)
                .is_some_and(|value| value == "reset-failed")
        })
        .collect::<Vec<_>>();
    assert_eq!(reset_calls.len(), 1);
    assert_eq!(
        reset_calls[0].arguments,
        ["--user", "reset-failed", "li_node.service"]
    );
    assert!(calls
        .iter()
        .all(|call| call.arguments != ["--user", "stop", "li_node.service"]));
    assert!(
        command_position(&calls, &["--user", "reset-failed", "li_node.service"])
            < command_position(&calls, &["--user", "daemon-reload"])
    );
    assert_eq!(
        calls.last().expect("last call").arguments,
        ["--user", "daemon-reload"]
    );

    io.take_mutations();
    queue_linux_states(&runner, &absent_linux_states());
    host.resume_retirement(&snapshot)
        .expect("replayed retirement");
    assert_eq!(runner.take_calls().len(), LINUX_IDENTITIES.len() * 2);
    assert!(io.files.lock().expect("files").is_empty());
}

// Preserves a failed unit definition when its exact reset command is rejected.
#[test]
fn linux_retirement_reset_failure_stops_before_definition_removal() {
    let (host, runner, io) = linux_host();
    let states = vec![
        ServiceState {
            file: Some(file("failed gateway", 0o600)),
            enablement: "disabled",
            activity: "failed",
            disabled: None,
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: None,
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: None,
        },
    ];
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    runner.take_calls();

    queue_linux_states(&runner, &states);
    runner.output(1, "");
    assert!(host.retire(&snapshot).is_err());
    assert_eq!(
        io.files
            .lock()
            .expect("files")
            .get(&linux_path("li_gateway.service")),
        states[0].file.as_ref()
    );
    assert!(io.take_mutations().is_empty());
    let calls = runner.take_calls();
    assert_eq!(
        calls.last().expect("reset failure").arguments,
        ["--user", "reset-failed", "li_gateway.service"]
    );
    assert!(calls
        .iter()
        .all(|call| call.arguments != ["--user", "daemon-reload"]));
}

// Resumes only the exact monotonic partial state left by an interrupted retirement.
#[test]
fn linux_partial_retirement_resumes_from_exact_original_files() {
    let (host, runner, io) = linux_host();
    let states = mixed_linux_states();
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    runner.take_calls();
    io.fail_once("remove", "li_node.service");
    queue_linux_states(&runner, &states);
    runner.successes(3);
    assert!(host.retire(&snapshot).is_err());
    runner.take_calls();

    let partial = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: None,
        },
        ServiceState {
            activity: "inactive",
            ..states[1].clone()
        },
        states[2].clone(),
    ];
    io.take_mutations();
    queue_linux_states(&runner, &partial);
    runner.output(0, "");
    host.resume_retirement(&snapshot)
        .expect("retirement replay");
    assert!(io.files.lock().expect("files").is_empty());
    assert_eq!(
        runner.take_calls().last().expect("reload").arguments,
        ["--user", "daemon-reload"]
    );
}

// Restores exact Linux bytes, modes, enablement, and only previously active residents.
#[test]
fn linux_restore_reconstructs_exact_files_and_safe_activity_order() {
    let (host, runner, io) = linux_host();
    let states = mixed_linux_states();
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    runner.take_calls();
    io.clear();

    queue_linux_states(&runner, &absent_linux_states());
    runner.successes(4);
    host.restore(&snapshot).expect("restore");
    let files = io.files.lock().expect("files");
    for (identity, state) in LINUX_IDENTITIES.iter().zip(&states) {
        assert_eq!(files.get(&linux_path(identity)), state.file.as_ref());
    }
    drop(files);
    let calls = runner.take_calls();
    let starts = calls
        .iter()
        .filter(|call| call.arguments.get(1).is_some_and(|value| value == "start"))
        .map(|call| call.arguments[2].as_str())
        .collect::<Vec<_>>();
    assert_eq!(starts, ["li_gateway.service"]);
    assert!(calls
        .iter()
        .any(|call| { call.arguments == ["--user", "disable", "li_node.service"] }));
}

// Treats systemd restart transitions as running work that restoration must explicitly stop.
#[test]
fn linux_restore_stops_activating_and_deactivating_restart_loops() {
    let (host, runner, io) = linux_host();
    let absent = absent_linux_states();
    queue_linux_states(&runner, &absent);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("absent snapshot");
    runner.take_calls();

    let current = LINUX_IDENTITIES
        .iter()
        .map(|identity| ServiceState {
            file: Some(file(identity, 0o600)),
            enablement: "enabled",
            activity: "active",
            disabled: None,
        })
        .collect::<Vec<_>>();
    install_linux_files(&io, &current);
    for activity in ["activating\n", "deactivating\n", "activating\n"] {
        runner.output(0, "enabled\n");
        runner.output(3, activity);
    }
    runner.successes(7);

    host.restore(&snapshot).expect("restore transient services");
    assert!(io.files.lock().expect("files").is_empty());
    let calls = runner.take_calls();
    for identity in LINUX_IDENTITIES {
        assert!(calls
            .iter()
            .any(|call| call.arguments == ["--user", "stop", identity]));
    }
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.arguments == ["--user", "daemon-reload"])
            .count(),
        1
    );
}

// Replays complete Linux restoration after a partial exact-file replacement failure.
#[test]
fn linux_partial_restore_can_be_retried_without_losing_snapshot_identity() {
    let (host, runner, io) = linux_host();
    let states = mixed_linux_states();
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    runner.take_calls();
    io.clear();
    io.fail_once("replace", "li_node.service");
    queue_linux_states(&runner, &absent_linux_states());
    assert!(host.restore(&snapshot).is_err());
    runner.take_calls();

    let partial = linux_states_from_files(&io);
    queue_linux_states(&runner, &partial);
    runner.successes(5);
    host.restore(&snapshot).expect("restore replay");
    let files = io.files.lock().expect("files");
    for (identity, state) in LINUX_IDENTITIES.iter().zip(&states) {
        assert_eq!(files.get(&linux_path(identity)), state.file.as_ref());
    }
}

// Maps an absent plist and launchctl status 113 to exact absence rather than unloaded state.
#[test]
fn macos_absence_mapping_preserves_absent_files() {
    let (host, runner, io, _) = macos_host();
    let states = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    for service in snapshot_json(&snapshot)["services"]
        .as_array()
        .expect("services")
    {
        assert_eq!(service["enablement"], "absent");
        assert_eq!(service["disabled"], false);
        assert!(service["definition"].is_null());
    }
    let schema: serde_json::Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/core/li_core_native_service_snapshot_v1.schema.json"),
        )
        .expect("schema bytes"),
    )
    .expect("schema JSON");
    assert!(schema["$defs"]["macos_service"]["required"]
        .as_array()
        .expect("required fields")
        .contains(&serde_json::json!("disabled")));
    runner.take_calls();
    let mut missing_disabled = snapshot_json(&snapshot);
    missing_disabled["services"][0]
        .as_object_mut()
        .expect("service")
        .remove("disabled");
    assert!(host.retire(&mutated_snapshot(&missing_disabled)).is_err());
    assert!(runner.take_calls().is_empty());
    assert!(io.take_mutations().is_empty());
}

// Accepts effective enabled absence and rejects ambiguous disabled-map grammar before mutation.
#[test]
fn macos_disabled_map_parser_is_closed_and_label_exact() {
    let (host, runner, io, _) = macos_host();
    runner.output(
        0,
        "disabled services = {\n\t\"unrelated.service\" => disabled\n}\n",
    );
    runner.output(113, "");
    runner.output(113, "");
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("effective enabled snapshot");
    assert!(snapshot_json(&snapshot)["services"]
        .as_array()
        .expect("services")
        .iter()
        .all(|service| service["disabled"] == false));

    for (status, output, print_count) in [
        (1, "", 1),
        (
            0,
            "disabled services = {\n\t\"ai.letsinfer.node\" => true\n}\n",
            2,
        ),
        (
            0,
            "disabled services = {\n\t\"ai.letsinfer.node\" => enabled\n\t\"ai.letsinfer.node\" => disabled\n}\n",
            2,
        ),
        (
            0,
            "disabled services = {\n\t\"ai.letsinfer.node\" => enabled\n",
            1,
        ),
    ] {
        let (host, runner, io, _) = macos_host();
        runner.output(status, output);
        for _ in 0..print_count {
            runner.output(113, "");
        }
        assert!(host
            .snapshot(context(CoreUpdateServicePlatform::Macos))
            .is_err());
        assert_eq!(runner.take_calls().len(), print_count + 1);
        assert!(io.take_mutations().is_empty());
    }
    assert!(io.take_mutations().is_empty());
}

// Rejects exact asymmetric state drift before bootout or plist mutation can begin.
#[test]
fn macos_asymmetric_snapshot_compare_and_swap_rejects_node_drift_without_mutation() {
    let (host, runner, io, _) = macos_host();
    let original = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("legacy rc.95 node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &original);
    queue_macos_states(&runner, &original);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.take_mutations();

    let drifted = vec![
        original[0].clone(),
        ServiceState {
            file: Some(file("concurrently changed node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &drifted);
    queue_macos_states(&runner, &drifted);
    assert_eq!(
        host.retire(&snapshot),
        Err(li_core_application::CoreServiceSetupError::RolledBack {
            reason: "native service state changed before retirement",
        })
    );
    assert!(io.take_mutations().is_empty());
    assert_eq!(runner.take_calls().len(), 3);
    assert_eq!(
        io.files
            .lock()
            .expect("files")
            .get(&macos_path("ai.letsinfer.node")),
        drifted[1].file.as_ref()
    );
    assert!(!io
        .files
        .lock()
        .expect("files")
        .contains_key(&macos_path("ai.letsinfer.gateway")));
    queue_macos_states(&runner, &drifted);
    assert_eq!(
        host.resume_retirement(&snapshot),
        Err(li_core_application::CoreServiceSetupError::RolledBack {
            reason: "native service state changed before retirement",
        })
    );
    assert!(io.take_mutations().is_empty());

    let disabled_drift = vec![
        original[0].clone(),
        ServiceState {
            disabled: Some(true),
            ..original[1].clone()
        },
    ];
    install_macos_files(&io, &disabled_drift);
    queue_macos_states(&runner, &disabled_drift);
    assert!(host.resume_retirement(&snapshot).is_err());
    assert!(io.take_mutations().is_empty());
}

// Separates strict initial CAS from one exact monotonic crash-retirement replay.
#[test]
fn macos_partial_retirement_requires_replay_authority_before_continuing() {
    let (host, runner, io, _) = macos_host();
    let original = vec![
        ServiceState {
            file: Some(file("legacy gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("legacy node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &original);
    queue_macos_states(&runner, &original);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.clear();
    io.insert(
        macos_path("ai.letsinfer.node"),
        original[1].file.clone().expect("node file"),
    );
    let partial = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        original[1].clone(),
    ];
    queue_macos_states(&runner, &partial);
    assert!(host.retire(&snapshot).is_err());
    assert!(io.take_mutations().is_empty());
    let initial_calls = runner.take_calls();
    assert!(initial_calls
        .iter()
        .all(|call| call.arguments.first().map(String::as_str) != Some("bootout")));
    assert_eq!(
        io.files
            .lock()
            .expect("files")
            .get(&macos_path("ai.letsinfer.node")),
        original[1].file.as_ref()
    );
    queue_macos_states(&runner, &partial);
    runner.output(0, "");
    host.resume_retirement(&snapshot)
        .expect("retirement replay");
    assert!(io.files.lock().expect("files").is_empty());
    assert!(runner
        .take_calls()
        .iter()
        .any(|call| call.arguments == ["bootout", "gui/501/ai.letsinfer.node"]));
}

// Treats one originally absent identity as a no-op during exact Prepared replay.
#[test]
fn macos_exact_replay_accepts_gateway_present_and_node_originally_absent() {
    let (host, runner, io, _) = macos_host();
    let original = vec![
        ServiceState {
            file: Some(file("legacy gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(true),
        },
    ];
    install_macos_files(&io, &original);
    queue_macos_states(&runner, &original);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.take_mutations();

    queue_macos_states(&runner, &original);
    runner.output(0, "");
    host.resume_retirement(&snapshot)
        .expect("exact retirement replay");
    assert!(io.files.lock().expect("files").is_empty());
    assert!(runner
        .take_calls()
        .iter()
        .any(|call| call.arguments == ["bootout", "gui/501/ai.letsinfer.gateway"]));
}

// Rejects an out-of-order retirement projection before any additional mutation.
#[test]
fn macos_replay_rejects_node_retired_before_gateway_without_mutation() {
    let (host, runner, io, _) = macos_host();
    let original = vec![
        ServiceState {
            file: Some(file("legacy gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("legacy node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &original);
    queue_macos_states(&runner, &original);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.clear();
    io.insert(
        macos_path("ai.letsinfer.gateway"),
        original[0].file.clone().expect("gateway file"),
    );
    let out_of_order = vec![
        original[0].clone(),
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    queue_macos_states(&runner, &out_of_order);
    assert_eq!(
        host.resume_retirement(&snapshot),
        Err(CoreServiceSetupError::RolledBack {
            reason: "native service state changed before retirement",
        })
    );
    assert!(io.take_mutations().is_empty());
    let calls = runner.take_calls();
    assert!(calls
        .iter()
        .all(|call| call.arguments.first().map(String::as_str) != Some("bootout")));
    assert_eq!(
        io.files
            .lock()
            .expect("files")
            .get(&macos_path("ai.letsinfer.gateway")),
        original[0].file.as_ref()
    );
}

// Preserves a plist that existed but was not loaded without inventing bootstrap activity.
#[test]
fn macos_unloaded_restore_writes_the_exact_plist_without_loading_it() {
    let (host, runner, io, _) = macos_host();
    let states = vec![
        ServiceState {
            file: Some(file("unloaded gateway", 0o644)),
            enablement: "unloaded",
            activity: "inactive",
            disabled: Some(true),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.clear();

    let absent = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    queue_macos_states(&runner, &absent);
    runner.output(0, "");
    runner.output(113, "");
    runner.output(0, "");
    runner.output(113, "");
    queue_macos_disabled(&runner, &states);
    host.restore(&snapshot).expect("restore");
    assert_eq!(
        io.files
            .lock()
            .expect("files")
            .get(&macos_path("ai.letsinfer.gateway")),
        states[0].file.as_ref()
    );
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 8);
    assert!(calls
        .iter()
        .any(|call| call.arguments == ["disable", "gui/501/ai.letsinfer.gateway"]));
    assert!(calls
        .iter()
        .any(|call| call.arguments == ["enable", "gui/501/ai.letsinfer.node"]));
    assert!(calls.iter().all(|call| !matches!(
        call.arguments.first().map(String::as_str),
        Some("bootstrap" | "kickstart")
    )));
}

// Restores loaded active and inactive jobs with exact bounded transient bootstrap retry.
#[test]
fn macos_loaded_restore_retries_exact_bootstrap_and_preserves_activity() {
    let (host, runner, io, waiter) = macos_host();
    let states = vec![
        ServiceState {
            file: Some(file("active gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(true),
        },
        ServiceState {
            file: Some(file("inactive node", 0o644)),
            enablement: "loaded",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.clear();

    let absent = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    queue_macos_states(&runner, &absent);
    runner.output(0, "");
    runner.diagnostic(5, "Bootstrap failed: 5: Input/output error\n");
    runner.diagnostic(5, "Bootstrap failed: 5: Input/output error\n");
    runner.output(0, "");
    runner.output(0, "service = {\n\tstate = waiting\n}\n");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "service = {\n\tstate = running\n}\n");
    queue_macos_disabled(&runner, &states);
    host.restore(&snapshot).expect("restore");
    assert_eq!(
        *waiter.durations.lock().expect("durations"),
        [Duration::from_millis(250), Duration::from_millis(250)]
    );
    let calls = runner.take_calls();
    let node_enable = command_position(&calls, &["enable", "gui/501/ai.letsinfer.node"]);
    assert!(calls[node_enable + 1].arguments[0] == "bootstrap");
    assert!(calls
        .iter()
        .all(|call| { call.arguments != ["disable", "gui/501/ai.letsinfer.node"] }));
    let gateway_enable = command_position(&calls, &["enable", "gui/501/ai.letsinfer.gateway"]);
    let gateway_bootstrap = calls
        .iter()
        .position(|call| {
            call.arguments.first().map(String::as_str) == Some("bootstrap")
                && call
                    .arguments
                    .last()
                    .is_some_and(|path| path.ends_with("ai.letsinfer.gateway.plist"))
        })
        .expect("Gateway bootstrap");
    let gateway_kickstart =
        command_position(&calls, &["kickstart", "-k", "gui/501/ai.letsinfer.gateway"]);
    let gateway_disable = command_position(&calls, &["disable", "gui/501/ai.letsinfer.gateway"]);
    assert!(gateway_enable < gateway_bootstrap);
    assert!(gateway_bootstrap < gateway_kickstart);
    assert!(gateway_kickstart < gateway_disable);
    let kickstarts = calls
        .iter()
        .filter(|call| {
            call.arguments
                .first()
                .is_some_and(|value| value == "kickstart")
        })
        .collect::<Vec<_>>();
    assert_eq!(kickstarts.len(), 1);
    assert!(kickstarts[0]
        .arguments
        .last()
        .is_some_and(|target| target.ends_with("ai.letsinfer.gateway")));
    let files = io.files.lock().expect("files");
    for (identity, state) in MACOS_IDENTITIES.iter().zip(&states) {
        assert_eq!(files.get(&macos_path(identity)), state.file.as_ref());
    }
}

// Restores an exact active 0600 Node and Gateway absence after full setup readiness rollback.
#[test]
fn macos_gateway_readiness_failure_restores_asymmetric_legacy_state_through_core_setup() {
    let (host, runner, io, _) = macos_host();
    let legacy = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("legacy rc.95 node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &legacy);
    queue_macos_states(&runner, &legacy);
    queue_macos_states(&runner, &legacy);
    runner.output(0, "");

    let rust_services = vec![
        ServiceState {
            file: Some(file("Rust gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("Rust node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    queue_macos_states(&runner, &rust_services);
    runner.successes(2);
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "service = {\n\tstate = running\n}\n");
    runner.output(0, "");
    runner.output(113, "");
    queue_macos_disabled(&runner, &legacy);

    let store = Arc::new(ExactCutoverStore::default());
    let cutover = Arc::new(DurableCoreServiceCutoverProvider::new(
        store.clone(),
        Arc::new(host),
    ));
    let setup = CoreServiceSetup::new_with_waiter(
        CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
        PathBuf::from("/Users/test/.local/share/letsinfer"),
        PathBuf::from("/Users/test/.local/share/letsinfer/configuration"),
        Arc::new(GatewayFailureSupervisor { io: io.clone() }),
        cutover,
        Arc::new(AcceptingPreflight),
        Arc::new(ReadyMacosHealth),
        Arc::new(DeadlineWaiter::default()),
    )
    .expect("setup");
    let installation = CoreInstallation::new(
        CoreVersion::parse("1.2.3").expect("version"),
        Sha256Digest::parse(&"a".repeat(64)).expect("identity"),
    );

    assert_eq!(
        setup.apply(&installation),
        Err(CoreServiceSetupError::RolledBack {
            reason: "a resident service did not become ready",
        })
    );
    assert!(store.record.lock().expect("record").is_none());
    let files = io.files.lock().expect("files");
    assert!(!files.contains_key(&macos_path("ai.letsinfer.gateway")));
    assert_eq!(
        files.get(&macos_path("ai.letsinfer.node")),
        legacy[1].file.as_ref()
    );
    drop(files);
    let calls = runner.take_calls();
    assert!(calls
        .iter()
        .any(|call| call.arguments == ["kickstart", "-k", "gui/501/ai.letsinfer.node"]));
    assert!(calls.iter().all(|call| {
        call.arguments.first().map(String::as_str) != Some("bootstrap")
            || !call
                .arguments
                .last()
                .is_some_and(|path| path.ends_with("ai.letsinfer.gateway.plist"))
    }));
}

// Retires loaded and unloaded launchd jobs repeatedly without treating absence as failure.
#[test]
fn macos_retirement_is_complete_and_idempotent() {
    for already_absent_status in [3, 113] {
        let (host, runner, io, _) = macos_host();
        let states = vec![
            ServiceState {
                file: Some(file("loaded gateway", 0o600)),
                enablement: "loaded",
                activity: "active",
                disabled: Some(false),
            },
            ServiceState {
                file: Some(file("unloaded node", 0o644)),
                enablement: "unloaded",
                activity: "inactive",
                disabled: Some(true),
            },
        ];
        install_macos_files(&io, &states);
        queue_macos_states(&runner, &states);
        let snapshot = host
            .snapshot(context(CoreUpdateServicePlatform::Macos))
            .expect("snapshot");
        runner.take_calls();
        queue_macos_states(&runner, &states);
        runner.output(already_absent_status, "");
        host.retire(&snapshot).expect("first retirement");
        assert!(io.files.lock().expect("files").is_empty());
        let calls = runner.take_calls();
        assert_eq!(
            calls.last().expect("bootout").arguments,
            ["bootout", "gui/501/ai.letsinfer.gateway"]
        );

        let absent = vec![
            ServiceState {
                file: None,
                enablement: "absent",
                activity: "inactive",
                disabled: Some(false),
            },
            ServiceState {
                file: None,
                enablement: "absent",
                activity: "inactive",
                disabled: Some(true),
            },
        ];
        queue_macos_states(&runner, &absent);
        host.resume_retirement(&snapshot)
            .expect("replayed retirement");
        assert_eq!(runner.take_calls().len(), MACOS_IDENTITIES.len() + 1);
    }
}

// Rejects every unrecognized launchd bootout status before removing any definition.
#[test]
fn macos_retirement_rejects_unrecognized_bootout_status_without_mutation() {
    let (host, runner, io, _) = macos_host();
    let states = vec![
        ServiceState {
            file: Some(file("loaded gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("unloaded node", 0o644)),
            enablement: "unloaded",
            activity: "inactive",
            disabled: Some(true),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    queue_macos_states(&runner, &states);
    runner.output(5, "");

    assert!(host.retire(&snapshot).is_err());
    let files = io.files.lock().expect("files");
    for (identity, state) in MACOS_IDENTITIES.iter().zip(&states) {
        assert_eq!(files.get(&macos_path(identity)), state.file.as_ref());
    }
}

// Rejects non-transient launchd bootstrap status without waiting or continuing restoration.
#[test]
fn macos_bootstrap_rejects_unrelated_status_five_without_retry() {
    let (host, runner, io, waiter) = macos_host();
    let states = vec![
        ServiceState {
            file: Some(file("loaded gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.clear();
    let absent = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    queue_macos_states(&runner, &absent);
    runner.output(0, "");
    runner.output(113, "");
    runner.output(0, "");
    runner.diagnostic(5, "Bootstrap failed: 5: permission denied\n");
    assert!(host.restore(&snapshot).is_err());
    assert!(waiter.durations.lock().expect("durations").is_empty());
    assert_eq!(
        runner
            .take_calls()
            .iter()
            .filter(|call| call
                .arguments
                .first()
                .is_some_and(|value| value == "bootstrap"))
            .count(),
        1
    );
}

// Stops launchd bootstrap after exactly thirty transient attempts and twenty-nine waits.
#[test]
fn macos_bootstrap_transient_retry_has_the_exact_global_bound() {
    let (host, runner, io, waiter) = macos_host();
    let states = vec![
        ServiceState {
            file: Some(file("loaded gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    runner.take_calls();
    io.clear();
    let absent = vec![
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
        ServiceState {
            file: None,
            enablement: "absent",
            activity: "inactive",
            disabled: Some(false),
        },
    ];
    queue_macos_states(&runner, &absent);
    runner.output(0, "");
    runner.output(113, "");
    runner.output(0, "");
    for _ in 0..30 {
        runner.diagnostic(5, "Bootstrap failed: 5: Input/output error\n");
    }
    assert!(host.restore(&snapshot).is_err());
    assert_eq!(waiter.durations.lock().expect("durations").len(), 29);
    assert_eq!(
        runner
            .take_calls()
            .iter()
            .filter(|call| call
                .arguments
                .first()
                .is_some_and(|value| value == "bootstrap"))
            .count(),
        30
    );
}

// Rejects malformed, foreign, duplicate, and tampered snapshot state before native observation.
#[test]
fn snapshot_mutation_matrix_fails_closed_before_service_mutation() {
    let (host, runner, io) = linux_host();
    let states = mixed_linux_states();
    install_linux_files(&io, &states);
    queue_linux_states(&runner, &states);
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .expect("snapshot");
    runner.take_calls();
    let original = snapshot_json(&snapshot);
    let mut mutations = Vec::new();

    let mut unknown = original.clone();
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unexpected".to_string(), serde_json::json!(true));
    mutations.push(unknown);

    let mut schema = original.clone();
    schema["schema"]["version"] = serde_json::json!(2);
    mutations.push(schema);

    let mut platform = original.clone();
    platform["platform"] = serde_json::json!("macos");
    mutations.push(platform);

    let mut duplicate_identity = original.clone();
    duplicate_identity["services"][1]["identity"] =
        duplicate_identity["services"][0]["identity"].clone();
    mutations.push(duplicate_identity);

    let mut unknown_state = original.clone();
    unknown_state["services"][2]["activity"] = serde_json::json!("starting");
    mutations.push(unknown_state);

    let mut tampered_bytes = original.clone();
    tampered_bytes["services"][0]["definition"]["bytes_base64"] = serde_json::json!("dGFtcGVyZWQ=");
    mutations.push(tampered_bytes);

    let mut tampered_identity = original.clone();
    tampered_identity["services"][0]["definition"]["sha256"] = serde_json::json!("f".repeat(64));
    mutations.push(tampered_identity);

    let mut unsafe_mode = original.clone();
    unsafe_mode["services"][0]["definition"]["mode"] = serde_json::json!(0o777);
    mutations.push(unsafe_mode);

    let mut unknown_file_field = original.clone();
    unknown_file_field["services"][0]["definition"]
        .as_object_mut()
        .expect("definition")
        .insert("path".to_string(), serde_json::json!("/tmp/foreign"));
    mutations.push(unknown_file_field);

    for mutation in mutations {
        assert!(host.retire(&mutated_snapshot(&mutation)).is_err());
        assert!(runner.take_calls().is_empty());
        assert!(io.take_mutations().is_empty());
    }

    let text = String::from_utf8(snapshot.bytes().to_vec()).expect("UTF-8 snapshot");
    let duplicate_platform = text.replacen(
        "\"platform\": \"linux\"",
        "\"platform\": \"linux\", \"platform\": \"linux\"",
        1,
    );
    let duplicate = CoreServiceCutoverNativeSnapshot::new(duplicate_platform.into_bytes())
        .expect("duplicate snapshot");
    assert!(host.retire(&duplicate).is_err());
    let malformed =
        CoreServiceCutoverNativeSnapshot::new(b"{not-json}".to_vec()).expect("malformed snapshot");
    assert!(host.retire(&malformed).is_err());
    assert!(runner.take_calls().is_empty());
    assert!(io.take_mutations().is_empty());
}

// Rejects truncated, duplicated, and unknown launchd state tokens during live observation.
#[test]
fn launchd_live_state_parser_fails_closed_on_ambiguous_output() {
    for output in [
        "last exit code = 0\n",
        "service = {\n\tstate = running\n\tstate = waiting\n}\n",
        "state = activating\n",
    ] {
        let (host, runner, io, _) = macos_host();
        io.insert(macos_path("ai.letsinfer.gateway"), file("gateway", 0o600));
        runner.output(0, "disabled services = {\n}\n");
        runner.output(0, output);
        assert!(host
            .snapshot(context(CoreUpdateServicePlatform::Macos))
            .is_err());
        assert!(io.take_mutations().is_empty());
        assert_eq!(runner.take_calls().len(), 2);
    }
}

// Accepts the direct running state while ignoring historical and nested coalition state.
#[test]
fn launchd_live_state_parser_accepts_the_complete_running_record() {
    let (host, runner, io, _) = macos_host();
    let states = vec![
        ServiceState {
            file: Some(file("gateway", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
        ServiceState {
            file: Some(file("node", 0o600)),
            enablement: "loaded",
            activity: "active",
            disabled: Some(false),
        },
    ];
    install_macos_files(&io, &states);
    queue_macos_disabled(&runner, &states);
    for _ in &states {
        runner.output(
            0,
            "service = {\n\tstate = running\n\tlast exit code = 1\n\tresource coalition = {\n\t\tstate = active\n\t}\n\tjetsam coalition = {\n\t\tstate = active\n\t}\n}\n",
        );
    }
    let snapshot = host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .expect("snapshot");
    assert!(snapshot_json(&snapshot)["services"]
        .as_array()
        .expect("services")
        .iter()
        .all(|service| service["activity"] == "active"));
    assert!(io.take_mutations().is_empty());
}

// Rejects unsupported systemd state and platform changes without proceeding through inventory.
#[test]
fn live_snapshot_boundary_rejects_foreign_platform_and_systemd_state() {
    let (host, runner, io) = linux_host();
    assert!(host
        .snapshot(context(CoreUpdateServicePlatform::Macos))
        .is_err());
    assert!(runner.take_calls().is_empty());
    runner.output(0, "masked\n");
    runner.output(3, "inactive\n");
    assert!(host
        .snapshot(context(CoreUpdateServicePlatform::Linux))
        .is_err());
    assert_eq!(runner.take_calls().len(), 2);
    assert!(io.take_mutations().is_empty());
}

// Exercises production no-follow I/O, exact modes, bounded files, and unsafe path rejection.
#[test]
fn system_file_io_preserves_exact_files_and_rejects_unsafe_paths() {
    let temporary = tempfile::tempdir().expect("temporary");
    let canonical = temporary
        .path()
        .canonicalize()
        .expect("canonical temporary");
    let home = canonical.join("home");
    let service_root = home.join(".config/systemd/user");
    fs::create_dir_all(&service_root).expect("service root");
    fs::set_permissions(&service_root, fs::Permissions::from_mode(0o700)).expect("root mode");
    let owner = fs::metadata(&service_root).expect("metadata").uid();
    let io = SystemCoreServiceCutoverFileIo;
    io.validate_root(&service_root, owner).expect("safe root");
    let path = service_root.join("li_node.service");
    let exact = file("exact native definition", 0o644);
    io.replace(&path, &exact, owner).expect("replace");
    assert_eq!(io.read(&path, owner).expect("read"), Some(exact.clone()));
    assert_eq!(
        fs::metadata(&path)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(io.remove(&path, owner).expect("remove"));
    assert!(!io.remove(&path, owner).expect("idempotent remove"));

    let source = service_root.join("source");
    fs::write(&source, b"source").expect("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
    symlink(&source, &path).expect("symlink");
    assert!(io.read(&path, owner).is_err());
    fs::remove_file(&path).expect("remove symlink");
    hard_link(&source, &path).expect("hardlink");
    assert!(io.read(&path, owner).is_err());
    fs::remove_file(&path).expect("remove hardlink");
    fs::remove_file(&source).expect("remove source");

    fs::write(&path, b"loose").expect("loose file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("loose mode");
    assert!(io.read(&path, owner).is_err());
    fs::remove_file(&path).expect("remove loose file");
    assert!(CoreServiceCutoverFile::new(Vec::new(), 0o600).is_err());
    assert!(CoreServiceCutoverFile::new(vec![b'x'; 64 * 1024 + 1], 0o600).is_err());
    assert!(CoreServiceCutoverFile::new(b"value".to_vec(), 0o777).is_err());

    let linked_home = canonical.join("linked-home");
    symlink(&home, &linked_home).expect("linked home");
    assert!(io
        .validate_root(&linked_home.join(".config/systemd/user"), owner)
        .is_err());
    fs::set_permissions(&service_root, fs::Permissions::from_mode(0o722)).expect("unsafe root");
    assert!(io.validate_root(&service_root, owner).is_err());
}

// Requires exact platform supervisor paths before validating or observing a service root.
#[test]
fn native_host_rejects_lookalike_supervisor_executables() {
    assert!(SystemCoreServiceCutoverNativeHost::new(
        CoreUpdateServicePlatform::Linux,
        PathBuf::from("/home/test"),
        1000,
        PathBuf::from("/tmp/systemctl"),
        Arc::new(CommandRunnerMock::default()),
        Arc::new(FileIoMock::default()),
    )
    .is_err());
    assert!(SystemCoreServiceCutoverNativeHost::new(
        CoreUpdateServicePlatform::Macos,
        PathBuf::from("/Users/test"),
        501,
        PathBuf::from("/usr/bin/launchctl"),
        Arc::new(CommandRunnerMock::default()),
        Arc::new(FileIoMock::default()),
    )
    .is_err());
}
