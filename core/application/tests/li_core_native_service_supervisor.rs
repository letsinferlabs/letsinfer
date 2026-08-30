// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, hard_link};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use li_core_application::{
    CoreNativeServiceCommandOutput, CoreNativeServiceCommandRunner, CoreNativeServiceIo,
    CoreNativeServiceSupervisor, CoreNativeServiceWaiter, CoreProcessLayout, CoreProcessPlatform,
    CoreResidentProcess, CoreServiceDefinition, CoreServiceDefinitionProvider,
    SystemCoreNativeServiceCommandRunner, SystemCoreNativeServiceIo,
    SystemCoreNativeServiceSupervisor,
};
use li_core_update_manager::{CoreUpdateError, CoreUpdateResidentService};

// Serializes fixtures that launch or forcibly terminate native supervisor commands.
static NATIVE_COMMAND_TEST_LOCK: Mutex<()> = Mutex::new(());

// Acquires exclusive ownership of native supervisor command fixtures for one complete test.
fn native_command_test_guard() -> MutexGuard<'static, ()> {
    NATIVE_COMMAND_TEST_LOCK
        .lock()
        .expect("native command test lock")
}

// Stores one exact native supervisor invocation for call-order assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandCall {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    maximum_stdout_bytes: usize,
}

// Returns queued command results and captures exact shell-free invocations.
#[derive(Default)]
struct CommandRunnerMock {
    outputs: Mutex<VecDeque<Result<CoreNativeServiceCommandOutput, CoreUpdateError>>>,
    calls: Mutex<Vec<CommandCall>>,
}

impl CommandRunnerMock {
    // Appends one deterministic native command result.
    fn output(&self, status: i32, stdout: &str) {
        self.outputs
            .lock()
            .expect("outputs")
            .push_back(Ok(CoreNativeServiceCommandOutput::new(
                status,
                stdout.as_bytes().to_vec(),
            )));
    }

    // Appends one deterministic native command result with exact standard error.
    fn output_with_stderr(&self, status: i32, stderr: &str) {
        self.outputs.lock().expect("outputs").push_back(Ok(
            CoreNativeServiceCommandOutput::new_with_stderr(
                status,
                Vec::new(),
                stderr.as_bytes().to_vec(),
            ),
        ));
    }

    // Returns and clears the exact command call sequence.
    fn take_calls(&self) -> Vec<CommandCall> {
        std::mem::take(&mut *self.calls.lock().expect("calls"))
    }
}

impl CoreNativeServiceCommandRunner for CommandRunnerMock {
    // Captures exact argv and returns the next queued result without process creation.
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
            .expect("queued output")
    }
}

// Captures launchd retry delays and injects one explicit wait failure when requested.
#[derive(Default)]
struct ServiceWaiterMock {
    durations: Mutex<Vec<Duration>>,
    fail: Mutex<bool>,
}

impl CoreNativeServiceWaiter for ServiceWaiterMock {
    // Records one exact delay or returns a redacted injected wait failure.
    fn wait(&self, duration: Duration) -> Result<(), CoreUpdateError> {
        self.durations.lock().expect("durations").push(duration);
        if *self.fail.lock().expect("fail") {
            return Err(CoreUpdateError::provider(
                "native service",
                "injected retry failure",
            ));
        }
        Ok(())
    }
}

// Stores exact definition bytes and captures mutation without touching native directories.
#[derive(Default)]
struct ServiceIoMock {
    files: Mutex<BTreeMap<PathBuf, Vec<u8>>>,
    events: Mutex<Vec<String>>,
}

impl ServiceIoMock {
    // Inserts one exact definition fixture at a native path.
    fn insert(&self, path: PathBuf, bytes: &[u8]) {
        self.files
            .lock()
            .expect("files")
            .insert(path, bytes.to_vec());
    }

    // Returns and clears the exact filesystem mutation sequence.
    fn take_events(&self) -> Vec<String> {
        std::mem::take(&mut *self.events.lock().expect("events"))
    }
}

impl CoreNativeServiceIo for ServiceIoMock {
    // Returns the exact optional in-memory definition.
    fn read_private_file(
        &self,
        path: &Path,
        _owner_user_id: u32,
        _maximum_bytes: u64,
    ) -> Result<Option<Vec<u8>>, CoreUpdateError> {
        Ok(self.files.lock().expect("files").get(path).cloned())
    }

    // Replaces one exact in-memory definition and records its mode.
    fn replace_private_file(
        &self,
        path: &Path,
        bytes: &[u8],
        _owner_user_id: u32,
        mode: u32,
    ) -> Result<(), CoreUpdateError> {
        self.events
            .lock()
            .expect("events")
            .push(format!("replace:{}:{mode:o}", path.display()));
        self.files
            .lock()
            .expect("files")
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }

    // Removes one exact in-memory definition and records whether it existed.
    fn remove_private_file(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, CoreUpdateError> {
        self.events
            .lock()
            .expect("events")
            .push(format!("remove:{}", path.display()));
        Ok(self.files.lock().expect("files").remove(path).is_some())
    }
}

// Generates one exact resident definition for native supervisor tests.
fn definition(
    platform: CoreProcessPlatform,
    process: CoreResidentProcess,
) -> CoreServiceDefinition {
    let layout = CoreProcessLayout::new(
        platform,
        PathBuf::from("/opt/letsinfer/core/versions/1.2.3/identity"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    CoreServiceDefinitionProvider
        .definition(platform, &layout.command(process).expect("command"))
        .expect("definition")
}

// Builds the exact closed systemctl show record for one loaded resident process.
fn systemd_loaded_identity(path: &Path, definition: &CoreServiceDefinition) -> String {
    let arguments = std::iter::once(definition.executable().as_os_str())
        .chain(
            definition
                .arguments()
                .iter()
                .map(std::ffi::OsString::as_os_str),
        )
        .map(|value| value.to_str().expect("argument"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "FragmentPath={}\nExecStart={{ path={} ; argv[]={arguments} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }}\nNeedDaemonReload=no\n",
        path.display(),
        definition.executable().display(),
    )
}

// Builds the exact closed launchctl print record for one loaded resident process.
fn launchd_loaded_identity(
    target: &str,
    path: &Path,
    definition: &CoreServiceDefinition,
    state: &str,
) -> String {
    let arguments = std::iter::once(definition.executable().as_os_str())
        .chain(
            definition
                .arguments()
                .iter()
                .map(std::ffi::OsString::as_os_str),
        )
        .map(|value| format!("\t\t{}\n", value.to_str().expect("argument")))
        .collect::<String>();
    format!(
        "{target} = {{\n\tpath = {}\n\tstate = {state}\n\tprogram = {}\n\targuments = {{\n{arguments}\t}}\n\tlast exit code = 1\n\tresource coalition = {{\n\t\tstate = active\n\t}}\n\tjetsam coalition = {{\n\t\tstate = active\n\t}}\n}}\n",
        path.display(),
        definition.executable().display(),
    )
}

// Composes one deterministic systemd user-service supervisor.
fn systemd_supervisor() -> (
    SystemCoreNativeServiceSupervisor,
    Arc<CommandRunnerMock>,
    Arc<ServiceIoMock>,
) {
    let runner = Arc::new(CommandRunnerMock::default());
    let io = Arc::new(ServiceIoMock::default());
    let supervisor = SystemCoreNativeServiceSupervisor::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/home/test"),
        1000,
        PathBuf::from("/usr/bin/systemctl"),
        runner.clone(),
        io.clone(),
    )
    .expect("supervisor");
    (supervisor, runner, io)
}

// Composes one deterministic launchd GUI-domain supervisor.
fn launchd_supervisor() -> (
    SystemCoreNativeServiceSupervisor,
    Arc<CommandRunnerMock>,
    Arc<ServiceIoMock>,
) {
    let runner = Arc::new(CommandRunnerMock::default());
    let io = Arc::new(ServiceIoMock::default());
    let supervisor = SystemCoreNativeServiceSupervisor::new(
        CoreProcessPlatform::Macos,
        PathBuf::from("/Users/test"),
        501,
        PathBuf::from("/bin/launchctl"),
        runner.clone(),
        io.clone(),
    )
    .expect("supervisor");
    (supervisor, runner, io)
}

// Composes one launchd supervisor whose retry waits are fully observable.
fn launchd_supervisor_with_waiter() -> (
    SystemCoreNativeServiceSupervisor,
    Arc<CommandRunnerMock>,
    Arc<ServiceIoMock>,
    Arc<ServiceWaiterMock>,
) {
    let runner = Arc::new(CommandRunnerMock::default());
    let io = Arc::new(ServiceIoMock::default());
    let waiter = Arc::new(ServiceWaiterMock::default());
    let supervisor = SystemCoreNativeServiceSupervisor::new_with_waiter(
        CoreProcessPlatform::Macos,
        PathBuf::from("/Users/test"),
        501,
        PathBuf::from("/bin/launchctl"),
        runner.clone(),
        io.clone(),
        waiter.clone(),
    )
    .expect("supervisor");
    (supervisor, runner, io, waiter)
}

// Rejects unsafe homes and noncanonical supervisor executables before deriving service paths.
#[test]
fn supervisor_derives_service_roots_only_from_safe_home_and_executable() {
    for home in ["relative", "/", "/home/test/../other"] {
        assert!(SystemCoreNativeServiceSupervisor::new(
            CoreProcessPlatform::Linux,
            PathBuf::from(home),
            1000,
            PathBuf::from("/usr/bin/systemctl"),
            Arc::new(CommandRunnerMock::default()),
            Arc::new(ServiceIoMock::default()),
        )
        .is_err());
    }
    for executable in [
        "/tmp/systemctl",
        "/bin/systemctl",
        "/usr/local/bin/systemctl",
        "/usr/bin/launchctl",
    ] {
        assert!(SystemCoreNativeServiceSupervisor::new(
            CoreProcessPlatform::Linux,
            PathBuf::from("/home/test"),
            1000,
            PathBuf::from(executable),
            Arc::new(CommandRunnerMock::default()),
            Arc::new(ServiceIoMock::default()),
        )
        .is_err());
    }
}

// Observes one exact enabled and active systemd definition by its complete byte identity.
#[test]
fn systemd_observation_binds_definition_enablement_and_activity() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
    io.insert(
        PathBuf::from("/home/test/.config/systemd/user/li_node.service"),
        definition.bytes(),
    );
    runner.output(0, "enabled\n");
    runner.output(0, "active\n");
    let state = supervisor
        .observe(CoreProcessPlatform::Linux, CoreResidentProcess::Node)
        .expect("state");
    assert_eq!(state.service(), CoreUpdateResidentService::Node);
    assert_eq!(state.loaded_identity(), Some(definition.sha256()));
    assert_eq!(state.active_identity(), Some(definition.sha256()));
    assert_eq!(runner.take_calls().len(), 2);
    assert!(io.take_events().is_empty());
}

// Refuses a definition whose systemd enablement no longer represents loaded state.
#[test]
fn systemd_observation_rejects_inconsistent_definition_state() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Gateway);
    io.insert(
        PathBuf::from("/home/test/.config/systemd/user/li_gateway.service"),
        definition.bytes(),
    );
    runner.output(1, "disabled\n");
    runner.output(3, "inactive\n");
    assert!(supervisor
        .observe(CoreProcessPlatform::Linux, CoreResidentProcess::Gateway)
        .is_err());
}

// Installs one systemd definition before reload, enable, and exact activity restoration.
#[test]
fn systemd_install_is_atomic_shell_free_and_ordered() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Watchdog);
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    supervisor.install(&definition, true).expect("install");
    assert_eq!(
        io.take_events(),
        vec!["replace:/home/test/.config/systemd/user/li_watchdog.service:600"]
    );
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].arguments, ["--user", "daemon-reload"]);
    assert_eq!(
        calls[1].arguments,
        ["--user", "enable", "li_watchdog.service"]
    );
    assert_eq!(
        calls[2].arguments,
        ["--user", "restart", "li_watchdog.service"]
    );
    assert!(calls
        .iter()
        .all(|call| call.executable == Path::new("/usr/bin/systemctl")));
}

// Verifies exact loaded bytes and exact absence without mutating either state.
#[test]
fn systemd_readiness_distinguishes_exact_definition_and_absence() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
    let path = PathBuf::from("/home/test/.config/systemd/user/li_node.service");
    io.insert(path.clone(), definition.bytes());
    runner.output(0, "enabled\n");
    runner.output(0, "active\n");
    runner.output(0, &systemd_loaded_identity(&path, &definition));
    assert!(supervisor
        .is_ready(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            Some(&definition),
            true,
        )
        .expect("ready"));
    io.files.lock().expect("files").remove(&path);
    runner.output(4, "not-found\n");
    runner.output(4, "inactive\n");
    assert!(supervisor
        .is_ready(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            None,
            false,
        )
        .expect("absent"));
    assert!(io.take_events().is_empty());
}

// Propagates one caller-owned readiness remainder through every native systemd command.
#[test]
fn systemd_readiness_commands_share_the_absolute_caller_deadline() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
    let path = PathBuf::from("/home/test/.config/systemd/user/li_node.service");
    io.insert(path.clone(), definition.bytes());
    runner.output(0, "enabled\n");
    runner.output(0, "active\n");
    runner.output(0, &systemd_loaded_identity(&path, &definition));
    assert!(supervisor
        .is_ready_with_timeout(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            Some(&definition),
            true,
            Duration::from_secs(7),
        )
        .expect("ready"));
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 3);
    assert!(calls
        .iter()
        .all(|call| !call.timeout.is_zero() && call.timeout <= Duration::from_secs(7)));
}

// Rejects stale, missing, duplicated, or ambiguous systemd loaded-process identity fields.
#[test]
fn systemd_readiness_fails_closed_on_loaded_process_identity_drift() {
    let variants = [
        "FragmentPath=/other/li_node.service\nExecStart={ path=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node ; argv[]=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node --configuration /var/lib/letsinfer/configuration/li_node.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }\nNeedDaemonReload=no\n",
        "FragmentPath=/home/test/.config/systemd/user/li_node.service\nNeedDaemonReload=no\n",
        "FragmentPath=/home/test/.config/systemd/user/li_node.service\nFragmentPath=/home/test/.config/systemd/user/li_node.service\nExecStart={ path=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node ; argv[]=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node --configuration /var/lib/letsinfer/configuration/li_node.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }\nNeedDaemonReload=no\n",
        "FragmentPath=/home/test/.config/systemd/user/li_node.service\nExecStart={ path=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node ; argv[]=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node --configuration /wrong.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }\nNeedDaemonReload=no\n",
        "FragmentPath=/home/test/.config/systemd/user/li_node.service\nExecStart={ path=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node ; argv[]=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node --configuration /var/lib/letsinfer/configuration/li_node.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }\nNeedDaemonReload=yes\n",
        "FragmentPath=/home/test/.config/systemd/user/li_node.service\nExecStart={ path=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node ; argv[]=/opt/letsinfer/core/versions/1.2.3/identity/bin/li_node --configuration /var/lib/letsinfer/configuration/li_node.json ; unknown=value }\nNeedDaemonReload=no\n",
    ];
    for variant in variants {
        let (supervisor, runner, io) = systemd_supervisor();
        let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
        io.insert(
            PathBuf::from("/home/test/.config/systemd/user/li_node.service"),
            definition.bytes(),
        );
        runner.output(0, "enabled\n");
        runner.output(0, "active\n");
        runner.output(0, variant);
        assert!(!matches!(
            supervisor.is_ready(
                CoreProcessPlatform::Linux,
                CoreResidentProcess::Node,
                Some(&definition),
                true,
            ),
            Ok(true)
        ));
        assert!(io.take_events().is_empty());
    }
}

// Binds launchd readiness to the exact label, plist path, program, and ordered argv.
#[test]
fn launchd_readiness_proves_exact_loaded_process_identity() {
    let (supervisor, runner, io) = launchd_supervisor();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Gateway);
    let path = PathBuf::from("/Users/test/Library/LaunchAgents/ai.letsinfer.gateway.plist");
    let target = "gui/501/ai.letsinfer.gateway";
    io.insert(path.clone(), definition.bytes());
    runner.output(0, "state = running\n");
    runner.output(
        0,
        &launchd_loaded_identity(target, &path, &definition, "running"),
    );
    assert!(supervisor
        .is_ready(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Gateway,
            Some(&definition),
            true,
        )
        .expect("ready"));
    assert_eq!(runner.take_calls().len(), 2);
    assert!(io.take_events().is_empty());
}

// Rejects launchd identity substitution, duplicate fields, and truncated argument blocks.
#[test]
fn launchd_readiness_fails_closed_on_loaded_process_identity_drift() {
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Node);
    let path = PathBuf::from("/Users/test/Library/LaunchAgents/ai.letsinfer.node.plist");
    let target = "gui/501/ai.letsinfer.node";
    let valid = launchd_loaded_identity(target, &path, &definition, "running");
    let variants = [
        valid.replace("program = /", "program = /other/"),
        valid.replace(
            "\tprogram = ",
            &format!("\tpath = {}\n\tprogram = ", path.display()),
        ),
        valid.replacen("\t}\n\tlast exit code", "\tlast exit code", 1),
        valid.replace(target, "gui/501/ai.letsinfer.gateway"),
    ];
    for variant in variants {
        let (supervisor, runner, io) = launchd_supervisor();
        io.insert(path.clone(), definition.bytes());
        runner.output(0, "state = running\n");
        runner.output(0, &variant);
        assert!(!matches!(
            supervisor.is_ready(
                CoreProcessPlatform::Macos,
                CoreResidentProcess::Node,
                Some(&definition),
                true,
            ),
            Ok(true)
        ));
        assert!(io.take_events().is_empty());
    }
}

// Restores prior absence through stop, disable, removal, and reload in exact order.
#[test]
fn systemd_restore_absence_removes_only_the_owned_service() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Gateway);
    io.insert(
        PathBuf::from("/home/test/.config/systemd/user/li_gateway.service"),
        definition.bytes(),
    );
    runner.output(0, "enabled\n");
    runner.output(0, "active\n");
    runner.output(0, "");
    runner.output(0, "disabled\n");
    runner.output(0, "");
    supervisor
        .restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Gateway,
            None,
            false,
        )
        .expect("restore");
    assert_eq!(io.take_events().len(), 1);
    let calls = runner.take_calls();
    assert_eq!(
        calls[0].arguments,
        ["--user", "is-enabled", "li_gateway.service"]
    );
    assert_eq!(
        calls[1].arguments,
        ["--user", "is-active", "li_gateway.service"]
    );
    assert_eq!(calls[2].arguments, ["--user", "stop", "li_gateway.service"]);
    assert_eq!(
        calls[3].arguments,
        ["--user", "disable", "li_gateway.service"]
    );
    assert_eq!(calls[4].arguments, ["--user", "daemon-reload"]);
}

// Replays restoration of prior absence without failing or inventing native mutations.
#[test]
fn systemd_restore_absence_is_idempotent_when_already_absent() {
    let (supervisor, runner, io) = systemd_supervisor();
    runner.output(4, "not-found\n");
    runner.output(4, "inactive\n");
    runner.output(0, "");
    supervisor
        .restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            None,
            false,
        )
        .expect("idempotent restore");
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].arguments, ["--user", "daemon-reload"]);
    assert_eq!(
        io.take_events(),
        vec!["remove:/home/test/.config/systemd/user/li_node.service"]
    );
}

// Proves systemd retirement replays after application-before-checkpoint and rejects replacement.
#[test]
fn systemd_retirement_accepts_only_active_reachable_partial_or_absent_planned_identity() {
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
    let expected = definition.sha256().clone();
    let path = PathBuf::from("/home/test/.config/systemd/user/li_node.service");

    let (supervisor, runner, io) = systemd_supervisor();
    io.insert(path.clone(), definition.bytes());
    runner.output(0, "enabled\n");
    runner.output(0, "active\n");
    runner.output(0, "");
    runner.output(0, "");
    supervisor
        .retire(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("active retirement");
    runner.output(4, "not-found\n");
    runner.output(3, "inactive\n");
    runner.output(0, "");
    supervisor
        .retire(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("absent replay");
    assert_eq!(io.take_events(), [format!("remove:{}", path.display())]);
    let calls = runner.take_calls();
    assert_eq!(
        calls[2].arguments,
        ["--user", "disable", "--now", "li_node.service"]
    );
    assert_eq!(calls[3].arguments, ["--user", "daemon-reload"]);
    assert_eq!(calls[6].arguments, ["--user", "daemon-reload"]);

    let (partial, partial_runner, partial_io) = systemd_supervisor();
    partial_io.insert(path.clone(), definition.bytes());
    partial_runner.output(1, "disabled\n");
    partial_runner.output(3, "inactive\n");
    partial_runner.output(0, "");
    partial
        .retire(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("disabled partial");
    assert_eq!(
        partial_io.take_events(),
        [format!("remove:{}", path.display())]
    );
    assert_eq!(
        partial_runner.take_calls()[2].arguments,
        ["--user", "daemon-reload"]
    );

    let (stopped, stopped_runner, stopped_io) = systemd_supervisor();
    stopped_io.insert(path.clone(), definition.bytes());
    stopped_runner.output(0, "enabled\n");
    stopped_runner.output(3, "inactive\n");
    stopped_runner.output(0, "");
    stopped_runner.output(0, "");
    stopped
        .retire(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("stopped-before-disable partial");
    assert_eq!(
        stopped_io.take_events(),
        [format!("remove:{}", path.display())]
    );
    let stopped_calls = stopped_runner.take_calls();
    assert_eq!(
        stopped_calls[2].arguments,
        ["--user", "disable", "--now", "li_node.service"]
    );
    assert_eq!(stopped_calls[3].arguments, ["--user", "daemon-reload"]);

    let (replacement, replacement_runner, replacement_io) = systemd_supervisor();
    replacement_io.insert(path, b"replacement definition");
    replacement_runner.output(0, "enabled\n");
    replacement_runner.output(0, "active\n");
    assert!(replacement
        .retire(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            &expected,
        )
        .is_err());
    assert!(replacement_io.take_events().is_empty());
    assert_eq!(replacement_runner.take_calls().len(), 2);
}

// Restores exact launchd absence without loading, enabling, or starting a replacement job.
#[test]
fn launchd_restore_absence_boots_out_only_when_loaded_and_removes_the_definition() {
    for loaded in [false, true] {
        let (supervisor, runner, io) = launchd_supervisor();
        let path = PathBuf::from("/Users/test/Library/LaunchAgents/ai.letsinfer.node.plist");
        io.insert(path.clone(), b"prior definition");
        if loaded {
            runner.output(0, "state = running\n");
            runner.output(0, "");
        } else {
            runner.output(113, "");
        }
        supervisor
            .restore(
                CoreProcessPlatform::Macos,
                CoreResidentProcess::Node,
                None,
                false,
            )
            .expect("restore absence");
        assert_eq!(io.take_events(), vec![format!("remove:{}", path.display())]);
        let calls = runner.take_calls();
        assert_eq!(calls[0].arguments, ["print", "gui/501/ai.letsinfer.node"]);
        assert_eq!(calls.len(), if loaded { 2 } else { 1 });
        if loaded {
            assert_eq!(calls[1].arguments, ["bootout", "gui/501/ai.letsinfer.node"]);
        }
        assert!(calls.iter().all(|call| {
            !matches!(
                call.arguments.first().map(String::as_str),
                Some("bootstrap" | "enable" | "kickstart")
            )
        }));
    }
}

// Proves launchd retirement replays after application-before-checkpoint and rejects replacement.
#[test]
fn launchd_retirement_accepts_only_active_reachable_partial_or_absent_planned_identity() {
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Node);
    let expected = definition.sha256().clone();
    let path = PathBuf::from("/Users/test/Library/LaunchAgents/ai.letsinfer.node.plist");

    let (supervisor, runner, io) = launchd_supervisor();
    io.insert(path.clone(), definition.bytes());
    runner.output(0, "state = running\n");
    runner.output(0, "");
    supervisor
        .retire(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("active retirement");
    runner.output(113, "");
    supervisor
        .retire(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("absent replay");
    assert_eq!(io.take_events(), [format!("remove:{}", path.display())]);
    let calls = runner.take_calls();
    assert_eq!(calls[1].arguments, ["bootout", "gui/501/ai.letsinfer.node"]);
    assert_eq!(calls.len(), 3);

    let (partial, partial_runner, partial_io) = launchd_supervisor();
    partial_io.insert(path.clone(), definition.bytes());
    partial_runner.output(113, "");
    partial
        .retire(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("unloaded partial");
    assert_eq!(
        partial_io.take_events(),
        [format!("remove:{}", path.display())]
    );
    assert_eq!(partial_runner.take_calls().len(), 1);

    let (stopped, stopped_runner, stopped_io) = launchd_supervisor();
    stopped_io.insert(path.clone(), definition.bytes());
    stopped_runner.output(0, "state = waiting\n");
    stopped_runner.output(0, "");
    stopped
        .retire(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Node,
            &expected,
        )
        .expect("loaded-before-bootout partial");
    assert_eq!(
        stopped_io.take_events(),
        [format!("remove:{}", path.display())]
    );
    let stopped_calls = stopped_runner.take_calls();
    assert_eq!(stopped_calls.len(), 2);
    assert_eq!(
        stopped_calls[1].arguments,
        ["bootout", "gui/501/ai.letsinfer.node"]
    );

    let (replacement, replacement_runner, replacement_io) = launchd_supervisor();
    replacement_io.insert(path, b"replacement definition");
    replacement_runner.output(0, "state = running\n");
    assert!(replacement
        .retire(
            CoreProcessPlatform::Macos,
            CoreResidentProcess::Node,
            &expected,
        )
        .is_err());
    assert!(replacement_io.take_events().is_empty());
    assert_eq!(replacement_runner.take_calls().len(), 1);
}

// Reloads one launchd definition through exact GUI-domain bootout/bootstrap/enable/kickstart argv.
#[test]
fn launchd_install_reloads_one_exact_active_agent() {
    let (supervisor, runner, io) = launchd_supervisor();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Gateway);
    io.insert(
        PathBuf::from("/Users/test/Library/LaunchAgents/ai.letsinfer.gateway.plist"),
        definition.bytes(),
    );
    runner.output(0, "state = running\n");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    supervisor.install(&definition, true).expect("install");
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 5);
    assert_eq!(
        calls[0].arguments,
        ["print", "gui/501/ai.letsinfer.gateway"]
    );
    assert_eq!(
        calls[1].arguments,
        ["bootout", "gui/501/ai.letsinfer.gateway"]
    );
    assert_eq!(
        calls[2].arguments[0..2],
        ["enable", "gui/501/ai.letsinfer.gateway"]
    );
    assert_eq!(calls[3].arguments[0], "bootstrap");
    assert_eq!(calls[4].arguments[0..2], ["kickstart", "-k"]);
    assert_eq!(io.take_events().len(), 1);
}

// Retries only transient launchd bootstrap status and preserves exact retry intervals.
#[test]
fn launchd_bootstrap_retries_transient_status_with_a_fixed_bound() {
    let (supervisor, runner, io, waiter) = launchd_supervisor_with_waiter();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Gateway);
    runner.output(113, "");
    runner.output(0, "");
    runner.output_with_stderr(5, "Bootstrap failed: 5: Input/output error\n");
    runner.output_with_stderr(5, "Bootstrap failed: 5: Input/output error\n");
    runner.output(0, "");
    runner.output(0, "");
    runner.output(0, "");
    supervisor.install(&definition, true).expect("install");
    assert_eq!(
        *waiter.durations.lock().expect("durations"),
        [Duration::from_millis(250), Duration::from_millis(250)]
    );
    let calls = runner.take_calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.arguments.first().map(String::as_str) == Some("bootstrap"))
            .count(),
        3
    );
    assert_eq!(io.take_events().len(), 1);
}

// Stops at the global bootstrap-attempt bound and propagates an injected retry-wait failure.
#[test]
fn launchd_bootstrap_exhaustion_and_wait_failure_remain_bounded() {
    let (supervisor, runner, io, waiter) = launchd_supervisor_with_waiter();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Gateway);
    runner.output(113, "");
    runner.output(0, "");
    for _ in 0..30 {
        runner.output_with_stderr(5, "Bootstrap failed: 5: Input/output error\n");
    }
    assert!(supervisor.install(&definition, true).is_err());
    assert_eq!(waiter.durations.lock().expect("durations").len(), 29);
    let calls = runner.take_calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.arguments.first().map(String::as_str) == Some("bootstrap"))
            .count(),
        30
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.arguments.first().map(String::as_str) == Some("enable"))
            .count(),
        1
    );
    assert!(calls
        .iter()
        .all(|call| call.arguments.first().map(String::as_str) != Some("kickstart")));
    assert_eq!(io.take_events().len(), 1);

    let (supervisor, runner, io, waiter) = launchd_supervisor_with_waiter();
    *waiter.fail.lock().expect("fail") = true;
    runner.output(113, "");
    runner.output(0, "");
    runner.output_with_stderr(5, "Bootstrap failed: 5: Input/output error\n");
    assert!(supervisor.install(&definition, true).is_err());
    assert_eq!(
        *waiter.durations.lock().expect("durations"),
        [Duration::from_millis(250)]
    );
    assert_eq!(runner.take_calls().len(), 3);
    assert_eq!(io.take_events().len(), 1);
}

// Stops immediately on a permanent bootstrap status without fabricating a retry.
#[test]
fn launchd_bootstrap_rejects_permanent_status_without_retry() {
    let (supervisor, runner, io, waiter) = launchd_supervisor_with_waiter();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Node);
    runner.output(113, "");
    runner.output(0, "");
    runner.output(64, "");
    assert!(supervisor.install(&definition, true).is_err());
    assert!(waiter.durations.lock().expect("durations").is_empty());
    assert_eq!(runner.take_calls().len(), 3);
    assert_eq!(io.take_events().len(), 1);
}

// Rejects status five when launchd did not report the exact transient input/output condition.
#[test]
fn launchd_bootstrap_does_not_retry_an_unrelated_status_five() {
    let (supervisor, runner, io, waiter) = launchd_supervisor_with_waiter();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Node);
    runner.output(113, "");
    runner.output(0, "");
    runner.output_with_stderr(5, "Bootstrap failed: 5: permission denied\n");
    assert!(supervisor.install(&definition, true).is_err());
    assert!(waiter.durations.lock().expect("durations").is_empty());
    assert_eq!(runner.take_calls().len(), 3);
    assert_eq!(io.take_events().len(), 1);
}

// Rejects an inactive launchd installation because the generated jobs are resident by contract.
#[test]
fn launchd_install_rejects_inactive_resident_state_before_mutation() {
    let (supervisor, runner, io) = launchd_supervisor();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Node);
    assert!(supervisor.install(&definition, false).is_err());
    assert!(runner.take_calls().is_empty());
    assert!(io.take_events().is_empty());
}

// Observes a loaded but inactive launchd agent without fabricating active identity.
#[test]
fn launchd_observation_preserves_inactive_loaded_state() {
    let (supervisor, runner, io) = launchd_supervisor();
    let definition = definition(CoreProcessPlatform::Macos, CoreResidentProcess::Node);
    io.insert(
        PathBuf::from("/Users/test/Library/LaunchAgents/ai.letsinfer.node.plist"),
        definition.bytes(),
    );
    runner.output(0, "state = exited\nlast exit code = 0\n");
    let state = supervisor
        .observe(CoreProcessPlatform::Macos, CoreResidentProcess::Node)
        .expect("state");
    assert_eq!(state.loaded_identity(), Some(definition.sha256()));
    assert_eq!(state.active_identity(), None);
}

// Distinguishes launchd's exact missing-service result from unrelated native failures.
#[test]
fn launchd_observation_accepts_only_exact_absence_status() {
    let (supervisor, runner, io) = launchd_supervisor();
    runner.output(113, "");
    let state = supervisor
        .observe(CoreProcessPlatform::Macos, CoreResidentProcess::Node)
        .expect("absent state");
    assert_eq!(state.loaded_identity(), None);
    assert_eq!(state.active_identity(), None);
    runner.output(1, "");
    assert!(supervisor
        .observe(CoreProcessPlatform::Macos, CoreResidentProcess::Node)
        .is_err());
    runner.output(0, "last exit code = 1\n");
    assert!(supervisor
        .observe(CoreProcessPlatform::Macos, CoreResidentProcess::Node)
        .is_err());
    assert!(io.take_events().is_empty());
}

// Rejects plausible systemd text carried by an impossible exit status.
#[test]
fn systemd_observation_rejects_invalid_status_token_combinations() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
    io.insert(
        PathBuf::from("/home/test/.config/systemd/user/li_node.service"),
        definition.bytes(),
    );
    runner.output(7, "enabled\n");
    runner.output(0, "active\n");
    assert!(supervisor
        .observe(CoreProcessPlatform::Linux, CoreResidentProcess::Node)
        .is_err());
}

// Removes a disabled definition without treating an unnecessary disable command as success.
#[test]
fn systemd_restore_disabled_definition_skips_disable_but_reloads_removal() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Gateway);
    io.insert(
        PathBuf::from("/home/test/.config/systemd/user/li_gateway.service"),
        definition.bytes(),
    );
    runner.output(1, "disabled\n");
    runner.output(3, "inactive\n");
    runner.output(0, "");
    supervisor
        .restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Gateway,
            None,
            false,
        )
        .expect("restore");
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].arguments, ["--user", "daemon-reload"]);
    assert!(calls
        .iter()
        .all(|call| !call.arguments.contains(&"disable".to_string())));
    assert_eq!(io.take_events().len(), 1);
}

// Completes the activity matrix by resetting only one exact failed systemd identity.
#[test]
fn systemd_restore_failed_definition_resets_only_the_owned_service() {
    let (supervisor, runner, io) = systemd_supervisor();
    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Node);
    let path = PathBuf::from("/home/test/.config/systemd/user/li_node.service");
    io.insert(path.clone(), definition.bytes());
    runner.output(1, "disabled\n");
    runner.output(3, "failed\n");
    runner.output(0, "");
    runner.output(0, "");

    supervisor
        .restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Node,
            None,
            false,
        )
        .expect("restore failed service absence");
    assert_eq!(io.take_events(), [format!("remove:{}", path.display())]);
    let calls = runner.take_calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[0].arguments,
        ["--user", "is-enabled", "li_node.service"]
    );
    assert_eq!(
        calls[1].arguments,
        ["--user", "is-active", "li_node.service"]
    );
    assert_eq!(
        calls[2].arguments,
        ["--user", "reset-failed", "li_node.service"]
    );
    assert_eq!(calls[3].arguments, ["--user", "daemon-reload"]);
}

// Rejects failed readiness and preserves the definition when its exact reset fails.
#[test]
fn systemd_failed_state_is_not_ready_and_reset_failure_is_closed() {
    let (supervisor, runner, io) = systemd_supervisor();
    runner.output(4, "not-found\n");
    runner.output(3, "failed\n");
    assert!(!supervisor
        .is_ready(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Gateway,
            None,
            false,
        )
        .expect("failed readiness observation"));
    assert!(io.take_events().is_empty());
    runner.take_calls();

    let definition = definition(CoreProcessPlatform::Linux, CoreResidentProcess::Gateway);
    let path = PathBuf::from("/home/test/.config/systemd/user/li_gateway.service");
    io.insert(path.clone(), definition.bytes());
    runner.output(1, "disabled\n");
    runner.output(3, "failed\n");
    runner.output(1, "");
    assert!(supervisor
        .restore(
            CoreProcessPlatform::Linux,
            CoreResidentProcess::Gateway,
            None,
            false,
        )
        .is_err());
    assert!(io.take_events().is_empty());
    assert_eq!(
        io.files
            .lock()
            .expect("files")
            .get(&path)
            .map(Vec::as_slice),
        Some(definition.bytes())
    );
    let calls = runner.take_calls();
    assert_eq!(
        calls.last().expect("reset failure").arguments,
        ["--user", "reset-failed", "li_gateway.service"]
    );
    assert!(calls
        .iter()
        .all(|call| call.arguments != ["--user", "daemon-reload"]));
}

// Rejects cross-platform calls and unsupported macOS Watchdog before native I/O or commands.
#[test]
fn supervisor_platform_and_process_mismatches_fail_before_mutation() {
    let (supervisor, runner, io) = launchd_supervisor();
    assert!(supervisor
        .observe(CoreProcessPlatform::Linux, CoreResidentProcess::Node)
        .is_err());
    assert!(supervisor
        .observe(CoreProcessPlatform::Macos, CoreResidentProcess::Watchdog)
        .is_err());
    assert!(runner.take_calls().is_empty());
    assert!(io.take_events().is_empty());
}

// Exercises production atomic I/O and rejects final-path symlinks and multiply linked files.
#[test]
fn system_service_io_is_atomic_owner_bound_and_no_follow() {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
    let owner = fs::metadata(temporary.path()).expect("root metadata").uid();
    let io = SystemCoreNativeServiceIo;
    let path = temporary.path().join("li_node.service");
    io.replace_private_file(&path, b"definition", owner, 0o600)
        .expect("replace");
    assert_eq!(
        io.read_private_file(&path, owner, 64).expect("read"),
        Some(b"definition".to_vec())
    );
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    io.remove_private_file(&path, owner).expect("remove");
    let source = temporary.path().join("source");
    fs::write(&source, b"definition").expect("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
    symlink(&source, &path).expect("symlink");
    assert!(io.read_private_file(&path, owner, 64).is_err());
    fs::remove_file(&path).expect("remove symlink");
    hard_link(&source, &path).expect("hard link");
    assert!(io.read_private_file(&path, owner, 64).is_err());
    fs::remove_file(&path).expect("remove hard link");
    fs::write(&path, b"definition").expect("write loose definition");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose mode");
    assert!(io.read_private_file(&path, owner, 64).is_err());
    assert!(io.remove_private_file(&path, owner).is_err());
    fs::remove_file(&path).expect("remove loose definition");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o722))
        .expect("unsafe root mode");
    assert!(io
        .replace_private_file(&path, b"definition", owner, 0o600)
        .is_err());
}

// Rejects a redirected service directory and invalid bounds before touching its target file.
#[test]
fn system_service_io_rejects_parent_redirection_and_invalid_bounds_without_mutation() {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
    let owner = fs::metadata(temporary.path()).expect("root metadata").uid();
    let actual = temporary.path().join("actual");
    let redirected = temporary.path().join("redirected");
    fs::create_dir(&actual).expect("actual directory");
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).expect("actual mode");
    symlink(&actual, &redirected).expect("redirected directory");
    let io = SystemCoreNativeServiceIo;
    let actual_path = actual.join("li_node.service");
    let redirected_path = redirected.join("li_node.service");
    io.replace_private_file(&actual_path, b"authoritative", owner, 0o600)
        .expect("authoritative definition");

    assert!(io.read_private_file(&redirected_path, owner, 64).is_err());
    assert!(io
        .replace_private_file(&redirected_path, b"replacement", owner, 0o600)
        .is_err());
    assert!(io.remove_private_file(&redirected_path, owner).is_err());
    assert_eq!(
        fs::read(&actual_path).expect("unchanged definition"),
        b"authoritative"
    );

    assert!(io.read_private_file(&actual_path, owner, 0).is_err());
    assert!(io.read_private_file(&actual_path, owner, u64::MAX).is_err());
    assert!(io
        .replace_private_file(&actual_path, b"replacement", owner, 0o644)
        .is_err());
    assert_eq!(
        fs::read(&actual_path).expect("bounded definition"),
        b"authoritative"
    );
}

// Exercises the production shell-free runner, cleared environment, and every execution bound.
#[test]
fn system_command_runner_executes_bounded_argv_without_inherited_shell() {
    let _command_guard = native_command_test_guard();
    let runner = SystemCoreNativeServiceCommandRunner;
    let output = runner
        .run(
            Path::new("/bin/echo"),
            &["li_native_service".to_string()],
            Duration::from_secs(1),
            64,
        )
        .expect("command");
    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"li_native_service\n");
    assert!(runner
        .run(
            Path::new("/bin/echo"),
            &["bad\nargument".to_string()],
            Duration::from_secs(1),
            64,
        )
        .is_err());
    assert!(runner
        .run(
            Path::new("/bin/echo"),
            &["value".to_string()],
            Duration::from_secs(1),
            0,
        )
        .is_err());
    let environment = runner
        .run(
            Path::new("/usr/bin/printenv"),
            &["PATH".to_string()],
            Duration::from_secs(1),
            64,
        )
        .expect("cleared environment");
    assert_ne!(environment.status(), 0);
    assert!(environment.stdout().is_empty());
    assert!(runner
        .run(
            Path::new("/bin/sleep"),
            &["1".to_string()],
            Duration::from_millis(10),
            64,
        )
        .is_err());
    assert!(runner
        .run(
            Path::new("/usr/bin/yes"),
            &["bounded".to_string()],
            Duration::from_secs(1),
            64,
        )
        .is_err());
}

// Applies one shared output limit across stdout and stderr without double-counting either stream.
#[test]
fn system_command_runner_bounds_combined_diagnostic_output_exactly() {
    let _command_guard = native_command_test_guard();
    let runner = SystemCoreNativeServiceCommandRunner;
    let arguments = [
        "/dev/null".to_string(),
        "/li_core_path_that_must_not_exist".to_string(),
    ];
    let observed = runner
        .run(
            Path::new("/bin/ls"),
            &arguments,
            Duration::from_secs(1),
            4_096,
        )
        .expect("mixed output");
    assert_ne!(observed.status(), 0);
    assert!(!observed.stdout().is_empty());
    assert!(!observed.stderr().is_empty());
    let exact_bound = observed.stdout().len() + observed.stderr().len();
    let exact = runner
        .run(
            Path::new("/bin/ls"),
            &arguments,
            Duration::from_secs(1),
            exact_bound,
        )
        .expect("exact combined bound");
    assert_eq!(exact.stdout(), observed.stdout());
    assert_eq!(exact.stderr(), observed.stderr());
    assert!(runner
        .run(
            Path::new("/bin/ls"),
            &arguments,
            Duration::from_secs(1),
            exact_bound - 1,
        )
        .is_err());
}

// Supplies only the closed current-user bus environment required by systemctl --user.
#[cfg(target_os = "linux")]
#[test]
fn system_command_runner_supplies_the_exact_systemd_user_bus_environment() {
    let _command_guard = native_command_test_guard();
    let temporary = tempfile::tempdir().expect("temporary");
    let executable = temporary.path().join("systemctl");
    fs::write(
        &executable,
        b"#!/bin/sh\nprintf '%s\\n%s\\n' \"$XDG_RUNTIME_DIR\" \"$DBUS_SESSION_BUS_ADDRESS\"\n",
    )
    .expect("fixture");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).expect("fixture mode");
    let runner = SystemCoreNativeServiceCommandRunner;
    let output = runner
        .run(
            &executable,
            &["--user".to_string()],
            Duration::from_secs(1),
            256,
        )
        .expect("systemctl fixture");
    let user_id = unsafe { libc::geteuid() };
    assert_eq!(
        output.stdout(),
        format!("/run/user/{user_id}\nunix:path=/run/user/{user_id}/bus\n").as_bytes()
    );
    assert!(output.stderr().is_empty());
}
