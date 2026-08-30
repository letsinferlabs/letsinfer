// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use li_runtime_manager::{
    CurlRuntimeHttpClient, RandomRuntimeHttpIdentityProvider, RuntimeBearerToken, RuntimeError,
    RuntimeHttpClient, RuntimeHttpCommand, RuntimeHttpCommandOutput, RuntimeHttpCommandRunner,
    RuntimeHttpIdentityProvider, RuntimeHttpRequest, RuntimeHttpWorkspaceIo,
    SystemRuntimeHttpCommandRunner, SystemRuntimeHttpWorkspaceIo,
};

// Returns one exact argv value following a named curl option.
fn option_value<'a>(command: &'a RuntimeHttpCommand, option: &str) -> &'a str {
    let index = command
        .arguments()
        .iter()
        .position(|value| value == option)
        .expect("option");
    command.arguments()[index + 1].as_str()
}

// Supplies one deterministic request identity.
struct MockIdentity {
    value: Mutex<String>,
    should_fail: AtomicBool,
}

impl MockIdentity {
    // Creates one deterministic identity provider.
    fn new(value: &str) -> Self {
        Self {
            value: Mutex::new(value.to_string()),
            should_fail: AtomicBool::new(false),
        }
    }
}

impl RuntimeHttpIdentityProvider for MockIdentity {
    // Returns the configured request identity or failure.
    fn request_id(&self) -> Result<String, RuntimeError> {
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(RuntimeError::DownloadUnavailable);
        }
        Ok(self.value.lock().expect("identity").clone())
    }
}

// Mocks curl while writing deterministic body and header files through exact argv.
struct MockRunner {
    commands: Mutex<Vec<RuntimeHttpCommand>>,
    process_status: Mutex<i32>,
    http_status: Mutex<u16>,
    final_url: Mutex<String>,
    headers: Mutex<Vec<u8>>,
    body: Mutex<Vec<u8>>,
    should_fail: AtomicBool,
    observed_authorization: AtomicBool,
}

impl MockRunner {
    // Creates one successful deterministic curl fixture.
    fn new() -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            process_status: Mutex::new(0),
            http_status: Mutex::new(200),
            final_url: Mutex::new("https://cdn.example.test/object".to_string()),
            headers: Mutex::new(
                b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://cdn.example.test/object\r\n\r\nHTTP/2 200\r\nContent-Type: application/json\r\nLink: <https://api.example.test/next>; rel=\"next\"\r\n\r\n".to_vec(),
            ),
            body: Mutex::new(b"{\"ready\":true}\n".to_vec()),
            should_fail: AtomicBool::new(false),
            observed_authorization: AtomicBool::new(false),
        }
    }
}

impl RuntimeHttpCommandRunner for MockRunner {
    // Materializes one configured response without contacting a network.
    fn run(
        &self,
        command: &RuntimeHttpCommand,
        _maximum_stdout_bytes: usize,
    ) -> Result<RuntimeHttpCommandOutput, RuntimeError> {
        self.commands
            .lock()
            .expect("commands")
            .push(command.clone());
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(RuntimeError::DownloadUnavailable);
        }
        if command.arguments().iter().any(|value| value == "--config") {
            let configuration = fs::read(option_value(command, "--config"))
                .map_err(|_| RuntimeError::DownloadUnavailable)?;
            self.observed_authorization.store(
                configuration.starts_with(b"header = \"Authorization: Bearer ")
                    && configuration.ends_with(b"\"\n"),
                Ordering::SeqCst,
            );
        }
        fs::write(
            option_value(command, "--dump-header"),
            self.headers.lock().expect("headers").as_slice(),
        )
        .map_err(|_| RuntimeError::DownloadUnavailable)?;
        fs::write(
            option_value(command, "--output"),
            self.body.lock().expect("body").as_slice(),
        )
        .map_err(|_| RuntimeError::DownloadUnavailable)?;
        Ok(RuntimeHttpCommandOutput::new(
            *self.process_status.lock().expect("status"),
            format!(
                "{}\n{}",
                *self.http_status.lock().expect("HTTP status"),
                self.final_url.lock().expect("final URL")
            )
            .into_bytes(),
        ))
    }
}

// Wraps real private filesystem behavior and fails one named native boundary.
struct FailingIo {
    system: SystemRuntimeHttpWorkspaceIo,
    step: Mutex<Option<&'static str>>,
}

impl FailingIo {
    // Creates one system-I/O wrapper with no configured failure.
    fn new() -> Self {
        Self {
            system: SystemRuntimeHttpWorkspaceIo,
            step: Mutex::new(None),
        }
    }

    // Returns whether one exact boundary is configured to fail.
    fn fails(&self, step: &'static str) -> bool {
        self.step.lock().expect("step").as_ref() == Some(&step)
    }
}

impl RuntimeHttpWorkspaceIo for FailingIo {
    // Creates one private workspace or returns the configured failure.
    fn create_workspace(&self, path: &Path) -> Result<(), RuntimeError> {
        if self.fails("create") {
            return Err(RuntimeError::DownloadUnavailable);
        }
        self.system.create_workspace(path)
    }

    // Writes authorization or returns the configured failure.
    fn write_authorization(
        &self,
        path: &Path,
        token: &RuntimeBearerToken,
    ) -> Result<(), RuntimeError> {
        if self.fails("authorization") {
            return Err(RuntimeError::DownloadUnavailable);
        }
        self.system.write_authorization(path, token)
    }

    // Reads headers or body with independently configurable failure.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
        let step = if path.ends_with("li_http_headers") {
            "headers"
        } else {
            "body"
        };
        if self.fails(step) {
            return Err(RuntimeError::DownloadUnavailable);
        }
        self.system.read(path, maximum_bytes)
    }

    // Hashes the body or returns the configured failure.
    fn identity(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<(u64, li_core_interface::Sha256Digest), RuntimeError> {
        if self.fails("identity") {
            return Err(RuntimeError::DownloadUnavailable);
        }
        self.system.identity(path, maximum_bytes)
    }

    // Activates the body or returns the configured failure.
    fn activate(&self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        if self.fails("activate") {
            return Err(RuntimeError::DownloadUnavailable);
        }
        self.system.activate(source, destination)
    }

    // Removes the workspace or returns the configured failure.
    fn remove_workspace(&self, path: &Path) -> Result<(), RuntimeError> {
        if self.fails("remove") {
            return Err(RuntimeError::DownloadUnavailable);
        }
        self.system.remove_workspace(path)
    }
}

// Creates one real-I/O, mocked-process client with retained boundaries.
fn client(
    directory: &tempfile::TempDir,
) -> (
    CurlRuntimeHttpClient,
    Arc<MockRunner>,
    Arc<MockIdentity>,
    Arc<FailingIo>,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let runner = Arc::new(MockRunner::new());
    let identity = Arc::new(MockIdentity::new(&"a".repeat(32)));
    let io = Arc::new(FailingIo::new());
    let client = CurlRuntimeHttpClient::new(
        PathBuf::from("/usr/bin/curl"),
        directory.path().to_path_buf(),
        runner.clone(),
        identity.clone(),
        io.clone(),
    )
    .expect("client");
    (client, runner, identity, io)
}

// Rejects credentials in URLs, unsafe transport, headers, tokens, and timeouts.
#[test]
fn request_validation_fails_at_every_public_boundary() {
    for url in [
        "http://example.test/object",
        "https://user@example.test/object",
        "https://example.test/object#fragment",
        "https:///missing-host",
    ] {
        assert!(RuntimeHttpRequest::https(url, None).is_err(), "url={url}");
    }
    assert!(
        RuntimeHttpRequest::new("http://localhost:5000/v2/object", None, None, true, 1,).is_ok()
    );
    assert!(RuntimeHttpRequest::new("http://192.168.1.1/object", None, None, true, 1,).is_err());
    assert!(RuntimeHttpRequest::new(
        "https://example.test/object",
        Some("application/json\nInjected: true".to_string()),
        None,
        false,
        1,
    )
    .is_err());
    assert!(RuntimeHttpRequest::new("https://example.test/object", None, None, false, 0,).is_err());
    for token in ["", "two words", "quoted\"token", "line\ntoken"] {
        assert!(RuntimeBearerToken::new(token).is_err(), "token shape");
    }
}

// Builds fixed HTTPS curl argv, parses the final header block, and cleans its workspace.
#[test]
fn metadata_get_is_shell_free_bounded_and_deterministic() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client, runner, _, _) = client(&directory);
    let request = RuntimeHttpRequest::https(
        "https://api.example.test/object",
        Some("application/json".to_string()),
    )
    .expect("request");
    let response = client.get(&request, 1024).expect("response");
    assert_eq!(response.status(), 200);
    assert_eq!(response.final_url(), "https://cdn.example.test/object");
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.body(), b"{\"ready\":true}\n");
    let command = &runner.commands.lock().expect("commands")[0];
    assert_eq!(command.executable(), Path::new("/usr/bin/curl"));
    for option in [
        "--disable",
        "--silent",
        "--location",
        "--max-filesize",
        "--proto",
        "--proto-redir",
    ] {
        assert!(command.arguments().iter().any(|value| value == option));
    }
    assert_eq!(option_value(command, "--proto"), "=https");
    assert_eq!(option_value(command, "--max-filesize"), "1024");
    assert!(directory.path().read_dir().expect("root").next().is_none());
}

// Keeps bearer bytes in a private file and disables automatic redirects for that request.
#[test]
fn bearer_request_never_places_or_forwards_secret_bytes_in_argv() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client, runner, _, _) = client(&directory);
    let token = "fixture-token-value";
    let request = RuntimeHttpRequest::new(
        "https://registry.example.test/v2/object",
        None,
        Some(RuntimeBearerToken::new(token).expect("token")),
        false,
        30,
    )
    .expect("request");
    client.get(&request, 1024).expect("response");
    let command = &runner.commands.lock().expect("commands")[0];
    assert!(command.arguments().iter().any(|value| value == "--config"));
    assert!(!command
        .arguments()
        .iter()
        .any(|value| value == "--location"));
    assert!(!command
        .arguments()
        .iter()
        .any(|value| value.contains(token)));
    assert!(runner.observed_authorization.load(Ordering::SeqCst));
    assert!(!format!("{request:?}").contains(token));
    assert!(directory.path().read_dir().expect("root").next().is_none());
}

// Executes registry HEAD with no response body and the same token-safe redirect policy.
#[test]
fn head_returns_only_metadata_and_uses_exact_native_method() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client, runner, _, _) = client(&directory);
    let request = RuntimeHttpRequest::new(
        "https://registry.example.test/v2/object",
        None,
        Some(RuntimeBearerToken::new("fixture-token").expect("token")),
        false,
        30,
    )
    .expect("request");
    let response = client.head(&request).expect("HEAD");
    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    let command = &runner.commands.lock().expect("commands")[0];
    assert!(command.arguments().iter().any(|value| value == "--head"));
    assert!(!command
        .arguments()
        .iter()
        .any(|value| value == "--location"));
}

// Streams a response to one exact destination and returns its measured identity.
#[test]
fn download_activates_exact_bytes_only_after_success() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client, runner, _, _) = client(&directory);
    let destination_root = directory.path().join("destination");
    fs::create_dir(&destination_root).expect("destination root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination_root, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    *runner.body.lock().expect("body") = b"downloaded bytes".to_vec();
    *runner.headers.lock().expect("headers") = b"HTTP/2 200\r\nContent-Length: 16\r\n\r\n".to_vec();
    let destination = destination_root.join("artifact");
    let request =
        RuntimeHttpRequest::https("https://example.test/artifact", None).expect("request");
    let result = client
        .download(&request, &destination, 16)
        .expect("download");
    assert_eq!(result.status(), 200);
    assert_eq!(result.bytes(), 16);
    assert_eq!(result.sha256().as_str().len(), 64);
    assert_eq!(fs::read(&destination).expect("bytes"), b"downloaded bytes");
    assert_eq!(directory.path().read_dir().expect("root").count(), 1);
}

// Rejects non-success HTTP status without activating its response body.
#[test]
fn download_http_failure_never_activates_body() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client, runner, _, _) = client(&directory);
    *runner.http_status.lock().expect("status") = 404;
    *runner.headers.lock().expect("headers") = b"HTTP/2 404\r\n\r\n".to_vec();
    let destination_root = directory.path().join("destination");
    fs::create_dir(&destination_root).expect("destination root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination_root, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    let destination = destination_root.join("artifact");
    assert_eq!(
        client
            .download(
                &RuntimeHttpRequest::https("https://example.test/missing", None).expect("request"),
                &destination,
                1024,
            )
            .expect_err("HTTP failure"),
        RuntimeError::DownloadUnavailable
    );
    assert!(!destination.exists());
}

// Fails closed on command status, malformed output, mismatched headers, and unsafe redirects.
#[test]
fn response_mutation_matrix_covers_every_process_boundary() {
    let request = RuntimeHttpRequest::https("https://example.test/object", None).expect("request");
    for mutation in ["runner", "status", "output", "headers", "redirect"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (client, runner, _, _) = client(&directory);
        match mutation {
            "runner" => runner.should_fail.store(true, Ordering::SeqCst),
            "status" => *runner.process_status.lock().expect("status") = 1,
            "output" => *runner.final_url.lock().expect("URL") = String::new(),
            "headers" => *runner.headers.lock().expect("headers") = b"HTTP/2 201\r\n\r\n".to_vec(),
            "redirect" => {
                *runner.final_url.lock().expect("URL") = "http://evil.test/object".to_string()
            }
            _ => unreachable!(),
        }
        assert!(client.get(&request, 1024).is_err(), "mutation={mutation}");
        assert!(directory.path().read_dir().expect("root").next().is_none());
    }
}

// Exercises failure at every injected workspace boundary with deterministic cleanup.
#[test]
fn workspace_failure_matrix_covers_all_get_and_download_paths() {
    for step in ["create", "headers", "body", "remove"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (client, _, _, io) = client(&directory);
        *io.step.lock().expect("step") = Some(step);
        assert!(
            client
                .get(
                    &RuntimeHttpRequest::https("https://example.test/object", None)
                        .expect("request"),
                    1024,
                )
                .is_err(),
            "step={step}"
        );
    }
    for step in ["identity", "activate", "remove"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (client, _, _, io) = client(&directory);
        let destination_root = directory.path().join("destination");
        fs::create_dir(&destination_root).expect("destination");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination_root, fs::Permissions::from_mode(0o700))
                .expect("private destination");
        }
        *io.step.lock().expect("step") = Some(step);
        assert!(
            client
                .download(
                    &RuntimeHttpRequest::https("https://example.test/object", None)
                        .expect("request"),
                    &destination_root.join("artifact"),
                    1024,
                )
                .is_err(),
            "step={step}"
        );
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let (client, _, _, io) = client(&directory);
    *io.step.lock().expect("step") = Some("authorization");
    assert!(client
        .get(
            &RuntimeHttpRequest::new(
                "https://example.test/object",
                None,
                Some(RuntimeBearerToken::new("fixture-token").expect("token")),
                false,
                1,
            )
            .expect("request"),
            1024,
        )
        .is_err());
}

// Rejects invalid client composition, request identity, and body bounds before process launch.
#[test]
fn client_composition_and_identity_fail_before_native_execution() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let runner = Arc::new(MockRunner::new());
    let identity = Arc::new(MockIdentity::new("invalid"));
    let io = Arc::new(FailingIo::new());
    assert!(CurlRuntimeHttpClient::new(
        PathBuf::from("curl"),
        directory.path().to_path_buf(),
        runner.clone(),
        identity.clone(),
        io.clone(),
    )
    .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let client = CurlRuntimeHttpClient::new(
        PathBuf::from("/usr/bin/curl"),
        directory.path().to_path_buf(),
        runner,
        identity,
        io,
    )
    .expect("client");
    assert_eq!(
        client
            .get(
                &RuntimeHttpRequest::https("https://example.test/object", None).expect("request"),
                1024,
            )
            .expect_err("identity"),
        RuntimeError::DownloadInvalid
    );
    assert!(client
        .get(
            &RuntimeHttpRequest::https("https://example.test/object", None).expect("request"),
            0,
        )
        .is_err());
}

// Generates canonical non-repeating request identities from system entropy.
#[test]
fn random_request_identities_are_canonical_and_nonrepeating() {
    let provider = RandomRuntimeHttpIdentityProvider;
    let first = provider.request_id().expect("first");
    let second = provider.request_id().expect("second");
    assert_eq!(first.len(), 32);
    assert!(first
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_ne!(first, second);
}

// Executes one benign native command with a closed shell-free runner contract.
#[test]
fn system_command_runner_executes_exact_argv_and_bounds_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let command = RuntimeHttpCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec!["ready".to_string()],
        directory.path().to_path_buf(),
    )
    .expect("command");
    let runner = SystemRuntimeHttpCommandRunner;
    assert_eq!(
        runner.run(&command, 5).expect("run"),
        RuntimeHttpCommandOutput::new(0, b"ready".to_vec())
    );
    assert_eq!(
        runner.run(&command, 4).expect_err("bound"),
        RuntimeError::DownloadInvalid
    );
}

// Enforces owner-only workspace, authorization, no-follow, activation, and removal behavior.
#[test]
fn system_workspace_io_enforces_private_filesystem_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let io = SystemRuntimeHttpWorkspaceIo;
    let workspace = directory.path().join("workspace");
    io.create_workspace(&workspace).expect("workspace");
    let authorization = workspace.join("authorization");
    io.write_authorization(
        &authorization,
        &RuntimeBearerToken::new("fixture-token").expect("token"),
    )
    .expect("authorization");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&authorization)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::os::unix::fs::symlink(&authorization, workspace.join("link")).expect("symlink");
        assert!(io.read(&workspace.join("link"), 1024).is_err());
        fs::remove_file(workspace.join("link")).expect("remove link");
    }
    let body = workspace.join("body");
    fs::write(&body, b"body").expect("body");
    let destination_root = directory.path().join("destination");
    fs::create_dir(&destination_root).expect("destination root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination_root, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    io.activate(&body, &destination_root.join("body"))
        .expect("activate");
    io.remove_workspace(&workspace).expect("remove");
    assert!(!workspace.exists());
}
