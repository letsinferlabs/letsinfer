// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use li_core_application::{
    CoreSetupIdentitySourceError, CoreSetupMachineIdentityCommandRunner,
    CoreSetupMachineIdentityFileReader, CoreSetupMachineIdentityProvider,
    LinuxCoreSetupMachineIdentityProvider, MacosCoreSetupMachineIdentityProvider,
    SystemCoreSetupMachineIdentityCommandRunner, SystemCoreSetupMachineIdentityFileReader,
};

const IOREG_ARGUMENTS: [&str; 3] = ["-rd1", "-c", "IOPlatformExpertDevice"];
const IOREG_MAXIMUM_OUTPUT_BYTES: usize = 64 * 1024;

// Serializes fixtures that launch or forcibly terminate machine-identity process groups.
static NATIVE_MACHINE_IDENTITY_TEST_LOCK: Mutex<()> = Mutex::new(());

// Acquires exclusive ownership of native machine-identity fixtures for one complete test.
fn native_machine_identity_test_guard() -> MutexGuard<'static, ()> {
    NATIVE_MACHINE_IDENTITY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// Returns one selected file document or stable provider failure.
struct TestFileReader {
    result: Result<Vec<u8>, CoreSetupIdentitySourceError>,
    calls: AtomicUsize,
    observations: Mutex<Vec<FileCall>>,
}

impl TestFileReader {
    // Creates one exact deterministic file-source fixture.
    fn new(result: Result<Vec<u8>, CoreSetupIdentitySourceError>) -> Self {
        Self {
            result,
            calls: AtomicUsize::new(0),
            observations: Mutex::new(Vec::new()),
        }
    }
}

impl CoreSetupMachineIdentityFileReader for TestFileReader {
    // Returns the injected result without touching the active filesystem.
    fn read(
        &self,
        path: &Path,
        owner_user_id: u32,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, CoreSetupIdentitySourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observations
            .lock()
            .expect("file observations")
            .push(FileCall {
                path: path.to_path_buf(),
                owner_user_id,
                maximum_bytes,
            });
        self.result.clone()
    }
}

// Captures one exact bounded machine-identity file observation.
#[derive(Debug, Eq, PartialEq)]
struct FileCall {
    path: PathBuf,
    owner_user_id: u32,
    maximum_bytes: usize,
}

// Records one exact command invocation and returns selected bounded stdout or failure.
struct TestCommandRunner {
    result: Result<Vec<u8>, CoreSetupIdentitySourceError>,
    calls: Mutex<Vec<CommandCall>>,
}

impl TestCommandRunner {
    // Creates one deterministic command-source fixture.
    fn new(result: Result<Vec<u8>, CoreSetupIdentitySourceError>) -> Self {
        Self {
            result,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl CoreSetupMachineIdentityCommandRunner for TestCommandRunner {
    // Records every explicit process input before returning the injected result.
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        owner_user_id: u32,
        timeout: Duration,
        poll_interval: Duration,
        maximum_stdout_bytes: usize,
    ) -> Result<Vec<u8>, CoreSetupIdentitySourceError> {
        self.calls.lock().expect("calls").push(CommandCall {
            executable: executable.to_path_buf(),
            arguments: arguments.iter().map(ToString::to_string).collect(),
            owner_user_id,
            timeout,
            poll_interval,
            maximum_stdout_bytes,
        });
        self.result.clone()
    }
}

// Captures one complete shell-free native process contract.
#[derive(Debug, Eq, PartialEq)]
struct CommandCall {
    executable: PathBuf,
    arguments: Vec<String>,
    owner_user_id: u32,
    timeout: Duration,
    poll_interval: Duration,
    maximum_stdout_bytes: usize,
}

// Proves Linux normalization accepts only the exact machine-id text forms.
#[test]
fn linux_provider_normalizes_exact_injected_machine_id_documents() {
    for bytes in [
        b"00112233445566778899aabbccddeeff".to_vec(),
        b"00112233445566778899aabbccddeeff\n".to_vec(),
    ] {
        let reader = Arc::new(TestFileReader::new(Ok(bytes)));
        let provider = LinuxCoreSetupMachineIdentityProvider::new(
            PathBuf::from("/etc/machine-id"),
            0,
            reader.clone(),
        );
        assert_eq!(
            provider.machine_id().expect("machine identity").as_str(),
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    }
}

// Proves production Linux identity is fixed to the root-owned system machine-id contract.
#[test]
fn linux_system_provider_uses_the_exact_trusted_native_source() {
    let reader = Arc::new(TestFileReader::new(Ok(
        b"00112233445566778899aabbccddeeff\n".to_vec(),
    )));
    let provider = LinuxCoreSetupMachineIdentityProvider::system(reader.clone());
    assert_eq!(
        provider.machine_id().expect("machine identity").as_str(),
        "00112233445566778899aabbccddeeff"
    );
    assert_eq!(
        *reader.observations.lock().expect("file observations"),
        vec![FileCall {
            path: PathBuf::from("/etc/machine-id"),
            owner_user_id: 0,
            maximum_bytes: 33,
        }]
    );
}

// Proves malformed, empty, oversized, zero, and failed Linux sources fail closed.
#[test]
fn linux_provider_rejects_invalid_and_failed_injected_sources() {
    for bytes in [
        Vec::new(),
        b"00112233445566778899aabbccddee".to_vec(),
        b"00112233445566778899aabbccddeeff\n\n".to_vec(),
        b"00112233445566778899AABBCCDDEEFF".to_vec(),
        b"00000000000000000000000000000000".to_vec(),
        vec![b'x'; 34],
        vec![0xff; 32],
    ] {
        let provider = LinuxCoreSetupMachineIdentityProvider::new(
            PathBuf::from("/etc/machine-id"),
            0,
            Arc::new(TestFileReader::new(Ok(bytes))),
        );
        assert_eq!(
            provider.machine_id(),
            Err(CoreSetupIdentitySourceError::Invalid)
        );
    }
    for error in [
        CoreSetupIdentitySourceError::Invalid,
        CoreSetupIdentitySourceError::Unavailable,
    ] {
        let provider = LinuxCoreSetupMachineIdentityProvider::new(
            PathBuf::from("/etc/machine-id"),
            0,
            Arc::new(TestFileReader::new(Err(error))),
        );
        assert_eq!(provider.machine_id(), Err(error));
    }
}

// Proves the system Linux reader accepts one stable exact-owner, exact-mode ordinary file.
#[test]
fn system_linux_reader_accepts_one_safe_machine_id_file() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let path = root.join("machine-id");
    write_mode(&path, b"00112233445566778899aabbccddeeff\n", 0o444);
    let provider = LinuxCoreSetupMachineIdentityProvider::new(
        path,
        owner_user_id(),
        Arc::new(SystemCoreSetupMachineIdentityFileReader),
    );
    assert_eq!(
        provider.machine_id().expect("machine identity").as_str(),
        "00112233445566778899aabbccddeeff"
    );
}

// Proves the system Linux reader rejects unsafe metadata, links, paths, and byte bounds.
#[test]
fn system_linux_reader_rejects_native_safety_and_size_matrix() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let safe = root.join("safe");
    write_mode(&safe, b"00112233445566778899aabbccddeeff\n", 0o444);
    let owner = owner_user_id();
    let reader = Arc::new(SystemCoreSetupMachineIdentityFileReader);

    let final_link = root.join("final-link");
    symlink(&safe, &final_link).expect("final symlink");
    assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
        final_link,
        owner,
        reader.clone(),
    ));

    let actual_parent = root.join("actual-parent");
    fs::create_dir(&actual_parent).expect("actual parent");
    let nested = actual_parent.join("machine-id");
    write_mode(&nested, b"00112233445566778899aabbccddeeff\n", 0o444);
    let parent_link = root.join("parent-link");
    symlink(&actual_parent, &parent_link).expect("parent symlink");
    assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
        parent_link.join("machine-id"),
        owner,
        reader.clone(),
    ));

    let writable = root.join("writable");
    write_mode(&writable, b"00112233445566778899aabbccddeeff\n", 0o644);
    assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
        writable,
        owner,
        reader.clone(),
    ));

    let hardlink_source = root.join("hardlink-source");
    let hardlink = root.join("hardlink");
    write_mode(
        &hardlink_source,
        b"00112233445566778899aabbccddeeff\n",
        0o444,
    );
    fs::hard_link(&hardlink_source, &hardlink).expect("hardlink");
    assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
        hardlink_source,
        owner,
        reader.clone(),
    ));

    assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
        safe,
        owner.saturating_add(1),
        reader.clone(),
    ));
    assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
        PathBuf::from("relative-machine-id"),
        owner,
        reader.clone(),
    ));

    for (name, bytes) in [("empty", Vec::new()), ("oversized", vec![b'x'; 34])] {
        let path = root.join(name);
        write_mode(&path, &bytes, 0o444);
        assert_source_failure(&LinuxCoreSetupMachineIdentityProvider::new(
            path,
            owner,
            reader.clone(),
        ));
    }
}

// Proves the production macOS source binds root-owned ioreg and normalizes its platform UUID.
#[test]
fn macos_system_provider_uses_exact_root_owned_ioreg_contract() {
    let runner = Arc::new(TestCommandRunner::new(Ok(
        b"{\n  \"IOPlatformUUID\" = \"00112233-4455-6677-8899-AABBCCDDEEFF\"\n}\n".to_vec(),
    )));
    let provider = MacosCoreSetupMachineIdentityProvider::system(
        PathBuf::from("/usr/sbin/ioreg"),
        Duration::from_secs(2),
        Duration::from_millis(5),
        runner.clone(),
    );
    assert_eq!(
        provider.machine_id().expect("machine identity").as_str(),
        "00112233445566778899aabbccddeeff"
    );
    assert_eq!(
        *runner.calls.lock().expect("calls"),
        vec![CommandCall {
            executable: PathBuf::from("/usr/sbin/ioreg"),
            arguments: IOREG_ARGUMENTS.iter().map(ToString::to_string).collect(),
            owner_user_id: 0,
            timeout: Duration::from_secs(2),
            poll_interval: Duration::from_millis(5),
            maximum_stdout_bytes: IOREG_MAXIMUM_OUTPUT_BYTES,
        }]
    );
}

// Proves empty, duplicate, malformed, oversized, zero, and failed ioreg outputs fail closed.
#[test]
fn macos_provider_rejects_invalid_and_failed_injected_outputs() {
    for output in [
        Vec::new(),
        b"no platform identity\n".to_vec(),
        b"\"IOPlatformUUID\" = \"invalid\"\n".to_vec(),
        b"\"IOPlatformUUID\" = \"00000000-0000-0000-0000-000000000000\"\n".to_vec(),
        b"\"IOPlatformUUID\" = \"00112233-4455-6677-8899-aabbccddeeff\"\n\"IOPlatformUUID\" = \"ffeeddcc-bbaa-9988-7766-554433221100\"\n".to_vec(),
        vec![b'x'; IOREG_MAXIMUM_OUTPUT_BYTES + 1],
        vec![0xff; 32],
    ] {
        let provider = MacosCoreSetupMachineIdentityProvider::new(
            PathBuf::from("/usr/sbin/ioreg"),
            0,
            Duration::from_secs(2),
            Duration::from_millis(5),
            Arc::new(TestCommandRunner::new(Ok(output))),
        );
        assert_eq!(
            provider.machine_id(),
            Err(CoreSetupIdentitySourceError::Invalid)
        );
    }
    for error in [
        CoreSetupIdentitySourceError::Invalid,
        CoreSetupIdentitySourceError::Unavailable,
    ] {
        let provider = MacosCoreSetupMachineIdentityProvider::new(
            PathBuf::from("/usr/sbin/ioreg"),
            0,
            Duration::from_secs(2),
            Duration::from_millis(5),
            Arc::new(TestCommandRunner::new(Err(error))),
        );
        assert_eq!(provider.machine_id(), Err(error));
    }
}

// Proves zero, inverted, and globally unbounded wait policies fail before runner entry.
#[test]
fn macos_provider_rejects_invalid_wait_bounds_before_process_entry() {
    for (timeout, poll_interval) in [
        (Duration::ZERO, Duration::from_millis(1)),
        (Duration::from_secs(1), Duration::ZERO),
        (Duration::from_millis(1), Duration::from_millis(2)),
        (Duration::from_secs(6), Duration::from_millis(1)),
    ] {
        let runner = Arc::new(TestCommandRunner::new(Ok(
            b"\"IOPlatformUUID\" = \"00112233-4455-6677-8899-AABBCCDDEEFF\"\n".to_vec(),
        )));
        let provider = MacosCoreSetupMachineIdentityProvider::new(
            PathBuf::from("/usr/sbin/ioreg"),
            0,
            timeout,
            poll_interval,
            runner.clone(),
        );
        assert_eq!(
            provider.machine_id(),
            Err(CoreSetupIdentitySourceError::Invalid)
        );
        assert!(runner.calls.lock().expect("calls").is_empty());
    }
}

// Proves the system command runner executes one safe shell-free source successfully.
#[test]
fn system_macos_runner_executes_one_safe_bounded_source() {
    let _process_guard = native_machine_identity_test_guard();
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let executable = root.join("ioreg");
    write_executable(
        &executable,
        "#!/bin/sh\nprintf '%s\\n' '\"IOPlatformUUID\" = \"00112233-4455-6677-8899-AABBCCDDEEFF\"'\n",
    );
    let provider = MacosCoreSetupMachineIdentityProvider::new(
        executable,
        owner_user_id(),
        Duration::from_secs(1),
        Duration::from_millis(5),
        Arc::new(SystemCoreSetupMachineIdentityCommandRunner),
    );
    assert_eq!(
        provider.machine_id().expect("machine identity").as_str(),
        "00112233445566778899aabbccddeeff"
    );
}

// Proves unsafe executables, timeout, nonzero status, and oversized stdout all fail closed.
#[test]
fn system_macos_runner_rejects_native_failure_matrix() {
    let _process_guard = native_machine_identity_test_guard();
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let owner = owner_user_id();
    let runner = Arc::new(SystemCoreSetupMachineIdentityCommandRunner);

    let unsafe_mode = root.join("unsafe-mode");
    write_executable(&unsafe_mode, "#!/bin/sh\nexit 0\n");
    fs::set_permissions(&unsafe_mode, fs::Permissions::from_mode(0o775))
        .expect("unsafe permissions");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        unsafe_mode,
        owner,
        Duration::from_secs(1),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let target = root.join("target");
    write_executable(&target, "#!/bin/sh\nexit 0\n");
    let executable_link = root.join("executable-link");
    symlink(&target, &executable_link).expect("executable symlink");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        executable_link,
        owner,
        Duration::from_secs(1),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let actual_parent = root.join("actual-executable-parent");
    fs::create_dir(&actual_parent).expect("actual executable parent");
    let nested_executable = actual_parent.join("ioreg");
    write_executable(&nested_executable, "#!/bin/sh\nexit 0\n");
    let executable_parent_link = root.join("executable-parent-link");
    symlink(&actual_parent, &executable_parent_link).expect("executable parent symlink");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        executable_parent_link.join("ioreg"),
        owner,
        Duration::from_secs(1),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let hardlink = root.join("executable-hardlink");
    fs::hard_link(&target, &hardlink).expect("executable hardlink");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        target,
        owner,
        Duration::from_secs(1),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let wrong_owner = root.join("wrong-owner");
    write_executable(&wrong_owner, "#!/bin/sh\nexit 0\n");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        wrong_owner,
        owner.saturating_add(1),
        Duration::from_secs(1),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let nonzero = root.join("nonzero");
    write_executable(&nonzero, "#!/bin/sh\nexit 7\n");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        nonzero,
        owner,
        Duration::from_secs(1),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let timeout = root.join("timeout");
    write_executable(&timeout, "#!/bin/sh\nwhile :; do :; done\n");
    assert_source_failure(&MacosCoreSetupMachineIdentityProvider::new(
        timeout,
        owner,
        Duration::from_millis(20),
        Duration::from_millis(5),
        runner.clone(),
    ));

    let oversized = root.join("oversized");
    write_executable(
        &oversized,
        &format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            "x".repeat(IOREG_MAXIMUM_OUTPUT_BYTES + 1)
        ),
    );
    let provider = MacosCoreSetupMachineIdentityProvider::new(
        oversized,
        owner,
        Duration::from_secs(5),
        Duration::from_millis(5),
        runner,
    );
    assert_eq!(
        provider.machine_id(),
        Err(CoreSetupIdentitySourceError::Invalid)
    );
}

// Proves timeout kills descendants which retain stdout after the direct child exits.
#[test]
fn system_macos_runner_kills_the_complete_inherited_stdout_process_group() {
    let _process_guard = native_machine_identity_test_guard();
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
    let executable = root.join("descendant");
    write_executable(
        &executable,
        "#!/bin/sh\n/bin/sleep 60 &\nprintf '%s\\n' '\"IOPlatformUUID\" = \"00112233-4455-6677-8899-AABBCCDDEEFF\"'\nexit 0\n",
    );
    let provider = MacosCoreSetupMachineIdentityProvider::new(
        executable,
        owner_user_id(),
        Duration::from_millis(100),
        Duration::from_millis(5),
        Arc::new(SystemCoreSetupMachineIdentityCommandRunner),
    );
    let started = Instant::now();
    assert_eq!(
        provider.machine_id(),
        Err(CoreSetupIdentitySourceError::Unavailable)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

// Proves all native source diagnostics remain path-free and value-free.
#[test]
fn machine_identity_errors_are_stable_and_redacted() {
    for error in [
        CoreSetupIdentitySourceError::Invalid,
        CoreSetupIdentitySourceError::Unavailable,
    ] {
        let message = error.to_string();
        assert!(!message.contains("machine-id"));
        assert!(!message.contains("ioreg"));
        assert!(!message.contains("00112233"));
        assert!(message.len() <= 64);
    }
}

// Returns the active native user identity for owner-bound temporary fixtures.
fn owner_user_id() -> u32 {
    unsafe { libc::geteuid() }
}

// Writes one exact test file and applies its selected native permission bits.
fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("file write");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("file permissions");
}

// Writes one direct executable fixture with the production exact mode.
fn write_executable(path: &Path, contents: &str) {
    write_mode(path, contents.as_bytes(), 0o755);
}

// Requires one provider to fail without coupling a safety test to an internal category.
fn assert_source_failure(provider: &dyn CoreSetupMachineIdentityProvider) {
    assert!(provider.machine_id().is_err());
}
