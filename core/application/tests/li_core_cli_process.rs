// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use li_core_application::{
    installed_core_cli_arguments, CoreCliConfiguration, CoreCliConfigurationFile,
    CoreCliConfigurationFileProvider, CoreCliProcess, CoreCliProcessArguments, CoreCliProcessError,
    CORE_CLI_CONFIGURATION_FILENAME, CORE_CLI_CONFIGURATION_SCHEMA_NAME,
    CORE_CLI_CONFIGURATION_SCHEMA_VERSION, MAXIMUM_CORE_CLI_CONFIGURATION_BYTES,
};
use li_core_cli::{native_cli_root_help, CliExitCode};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_node_manager::{
    NodeCommandAuditMarker, NodeCommandAuditOpenDisposition, NodeCommandAuditOpenReceipt,
    NodeHostInventory, NodeHostProjectionValue, NodeHostSnapshot, NodePrivateRequest,
    NodePrivateResponse, NodePrivateTransport, NodePrivateTransportOutcome,
    NodePrivateTransportResponse,
};
use serde_json::{json, Value};

// Serializes fixtures that launch the complete installed native CLI process.
static NATIVE_CLI_PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

// Acquires exclusive ownership of installed native CLI fixtures for one complete test.
fn native_cli_process_test_guard() -> MutexGuard<'static, ()> {
    NATIVE_CLI_PROCESS_TEST_LOCK
        .lock()
        .expect("native CLI process test lock")
}

// Supplies one descriptor-shaped result and records the exact bounded read request.
struct ConfigurationFileMock {
    result: Result<CoreCliConfigurationFile, CoreCliProcessError>,
    calls: Mutex<Vec<(PathBuf, usize)>>,
}

// Derives one stable home configuration path from an immutable release executable only.
#[test]
fn installed_launcher_supplies_stable_configuration_without_current_or_version_binding() {
    let executable = Path::new("/Users/home/.local/share/letsinfer/core/versions/1.2.3/")
        .join("a".repeat(64))
        .join("bin/li_letsinfer");
    let arguments = installed_core_cli_arguments(
        &executable,
        [OsString::from("node"), OsString::from("info")],
    )
    .expect("installed launcher arguments");
    assert_eq!(
        arguments,
        [
            OsString::from("--configuration"),
            OsString::from(format!(
                "/Users/home/.local/share/letsinfer/configuration/{CORE_CLI_CONFIGURATION_FILENAME}"
            )),
            OsString::from("--"),
            OsString::from("node"),
            OsString::from("info"),
        ]
    );
    assert!(!arguments.iter().any(|value| value == "current"));
    assert!(!arguments.iter().any(|value| value == "1.2.3"));

    for invalid in [
        Path::new("/tmp/li_letsinfer").to_path_buf(),
        Path::new("/home/core/current/bin/li_letsinfer").to_path_buf(),
        Path::new("/home/core/versions/1.2.3/not-a-digest/bin/li_letsinfer").to_path_buf(),
        Path::new("/home/core/versions/not-a-version/")
            .join("a".repeat(64))
            .join("bin/li_letsinfer"),
    ] {
        assert_eq!(
            installed_core_cli_arguments(&invalid, [OsString::from("status")]),
            Err(CoreCliProcessError::InvalidArguments)
        );
    }
}

impl ConfigurationFileMock {
    // Creates one deterministic configuration-file provider.
    fn new(result: Result<CoreCliConfigurationFile, CoreCliProcessError>) -> Self {
        Self {
            result,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl CoreCliConfigurationFileProvider for ConfigurationFileMock {
    // Returns the injected descriptor observation without performing native I/O.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<CoreCliConfigurationFile, CoreCliProcessError> {
        self.calls
            .lock()
            .expect("configuration calls")
            .push((path.to_path_buf(), maximum_bytes));
        self.result.clone()
    }
}

// Creates one canonical main-node snapshot for real local transport responses.
fn local_node() -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node identity"),
            MachineId::parse(&"2".repeat(32)).expect("machine identity"),
            InstallationId::parse(&"3".repeat(64)).expect("installation identity"),
        ),
        DisplayName::parse("homeai").expect("display name"),
        NodeRole::Main,
        NodeState::Active,
        NodeAddress::parse("homeai.local:9770").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
}

// Creates one truthful local-only host inventory for the public Node information command.
fn local_host_inventory(node: &Node) -> NodeHostInventory {
    let host = NodeHostSnapshot::restore(
        node.clone(),
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::Available(Vec::new()),
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::NotApplicable,
        NodeHostProjectionValue::Unavailable,
        NodeHostProjectionValue::NotApplicable,
    )
    .expect("local host projection");
    NodeHostInventory::new(
        node.identity().node_id().clone(),
        vec![host],
        NodeHostProjectionValue::Available(Vec::new()),
    )
    .expect("local host inventory")
}

// Creates one exact private bootstrap prefix followed by ordinary command arguments.
fn bootstrap(configuration: &Path, command: &[&str]) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("--configuration"),
        configuration.as_os_str().to_owned(),
        OsString::from("--"),
    ];
    arguments.extend(command.iter().map(OsString::from));
    arguments
}

// Creates one closed configuration document for explicit native paths and client bounds.
fn configuration_document(socket: &Path, entropy: &Path) -> Value {
    json!({
        "schema": {
            "name": CORE_CLI_CONFIGURATION_SCHEMA_NAME,
            "version": CORE_CLI_CONFIGURATION_SCHEMA_VERSION
        },
        "local_node_socket": socket,
        "entropy_source": entropy,
        "client": {
            "timeout_milliseconds": 1_000,
            "maximum_response_bytes": 1_048_576
        },
        "pairing": {
            "node_configuration_file": "/var/lib/letsinfer/configuration/li_node_configuration.json",
            "installation": {
                "version": "0.11.0-rc.114",
                "source_identity": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "watchdog_health": null
        },
        "uninstall": {
            "launcher_file": "/usr/local/bin/letsinfer",
            "privilege_command": "/usr/bin/sudo"
        },
        "remote_main": null
    })
}

// Serializes one configuration value through the same canonical JSON implementation as fixtures.
fn configuration_bytes(document: &Value) -> Vec<u8> {
    serde_json::to_vec(document).expect("configuration JSON")
}

// Wraps bytes in the exact safe descriptor metadata required by the loader.
fn safe_configuration_file(bytes: Vec<u8>) -> CoreCliConfigurationFile {
    CoreCliConfigurationFile::new(unsafe { libc::geteuid() }, 0o600, 1, true, bytes)
}

// Returns one canonical SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one opaque command-audit marker for the deterministic local process fixture.
fn audit_marker() -> NodeCommandAuditMarker {
    NodeCommandAuditMarker::parse(&format!(
        "li_cli_audit_{}_{}",
        digest('b').as_str(),
        digest('e').as_str()
    ))
    .expect("audit marker")
}

// Creates one configuration provider for the real socket and entropy fixture.
fn fixture_configuration_provider(socket: &Path, entropy: &Path) -> ConfigurationFileMock {
    ConfigurationFileMock::new(Ok(safe_configuration_file(configuration_bytes(
        &configuration_document(socket, entropy),
    ))))
}

// Accepts one real Unix connection before a fixed test deadline.
fn accept_before(listener: &UnixListener, deadline: Instant) -> UnixStream {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "bounded accept");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
}

// Reads one complete fixture frame across retryable native interruptions before the fixed deadline.
fn read_exact_before(stream: &mut UnixStream, mut buffer: &mut [u8], deadline: Instant) {
    while !buffer.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .expect("bounded fixture read");
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_secs(1))))
            .expect("server read timeout");
        match stream.read(buffer) {
            Ok(0) => panic!("request ended before its complete frame"),
            Ok(count) => {
                let (_, unread) = buffer.split_at_mut(count);
                buffer = unread;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("request read failed: {error}"),
        }
    }
}

// Serves exact correlated responses and records every typed request received by the Node socket.
fn serve_local_node(
    listener: UnixListener,
    responses: Vec<NodePrivateResponse>,
    requests: Arc<Mutex<Vec<NodePrivateRequest>>>,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    for response in responses {
        let mut stream = accept_before(&listener, deadline);
        stream
            .set_nonblocking(false)
            .expect("blocking fixture stream");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("server write timeout");
        let mut header = [0_u8; 4];
        read_exact_before(&mut stream, &mut header, deadline);
        let mut document = vec![0_u8; u32::from_be_bytes(header) as usize];
        read_exact_before(&mut stream, &mut document, deadline);
        let request = NodePrivateTransport::decode_request(&document).expect("typed request");
        requests
            .lock()
            .expect("requests")
            .push(request.request().clone());
        let response = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
            request.request_id().clone(),
            NodePrivateTransportOutcome::Success(response),
        ))
        .expect("typed response");
        stream
            .write_all(&u32::try_from(response.len()).expect("length").to_be_bytes())
            .expect("response header");
        stream.write_all(&response).expect("response document");
    }
}

// Creates a real private socket and entropy source for one bounded process invocation.
fn native_fixture(
    responses: Vec<NodePrivateResponse>,
) -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    thread::JoinHandle<()>,
    Arc<Mutex<Vec<NodePrivateRequest>>>,
) {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let socket = root.join("node.sock");
    let listener = UnixListener::bind(&socket).expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("private socket");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_requests = Arc::clone(&requests);
    let server = thread::spawn(move || serve_local_node(listener, responses, server_requests));
    let entropy = root.join("entropy");
    fs::write(&entropy, vec![0x5a; 96]).expect("entropy");
    (directory, socket, entropy, server, requests)
}

// Parses only the hidden configuration prefix and preserves the public command vector.
#[test]
fn process_arguments_are_closed_and_command_preserving() {
    let configuration = Path::new("/var/lib/letsinfer/li_core_cli_configuration.json");
    let valid = bootstrap(configuration, &["node", "info", "--json"]);
    let parsed = CoreCliProcessArguments::parse(valid.clone()).expect("arguments");
    assert_eq!(parsed.configuration_file(), configuration);
    assert_eq!(parsed.command_arguments(), ["node", "info", "--json"]);

    let mutations = [
        valid[..3].to_vec(),
        vec![
            OsString::from("--config"),
            configuration.as_os_str().to_owned(),
            OsString::from("--"),
            OsString::from("status"),
        ],
        vec![
            OsString::from("--configuration"),
            OsString::from("relative.json"),
            OsString::from("--"),
            OsString::from("status"),
        ],
        vec![
            OsString::from("--configuration"),
            configuration.as_os_str().to_owned(),
            OsString::from("status"),
            OsString::from("--json"),
        ],
        vec![
            OsString::from("--configuration"),
            configuration.as_os_str().to_owned(),
            OsString::from("--"),
            OsString::from_vec(vec![0xff]),
        ],
    ];
    for mutation in mutations {
        assert_eq!(
            CoreCliProcessArguments::parse(mutation),
            Err(CoreCliProcessError::InvalidArguments)
        );
    }
}

// Loads one exact closed fixture and projects only its local client inputs.
#[test]
fn configuration_loader_accepts_the_closed_fixture_and_client_bounds() {
    let path = Path::new("/var/lib/letsinfer/li_core_cli_configuration.json");
    let socket = Path::new("/var/run/user/501/letsinfer/node.sock");
    let entropy = Path::new("/dev/urandom");
    let provider = fixture_configuration_provider(socket, entropy);
    let configuration = CoreCliConfiguration::load(path, unsafe { libc::geteuid() }, &provider)
        .expect("configuration");
    assert_eq!(configuration.local_node_socket(), socket);
    assert_eq!(configuration.entropy_source(), entropy);
    assert_eq!(configuration.client().timeout(), Duration::from_secs(1));
    assert_eq!(configuration.client().maximum_response_bytes(), 1_048_576);
    assert_eq!(
        configuration.pairing().node_configuration_file(),
        Path::new("/var/lib/letsinfer/configuration/li_node_configuration.json")
    );
    assert_eq!(
        configuration.pairing().installation().version().as_str(),
        "0.11.0-rc.114"
    );
    assert!(configuration.pairing().watchdog_health().is_none());
    assert_eq!(
        configuration.uninstall().launcher_file(),
        Path::new("/usr/local/bin/letsinfer")
    );
    assert_eq!(
        configuration.uninstall().privilege_command(),
        Some(Path::new("/usr/bin/sudo"))
    );
    assert_eq!(
        *provider.calls.lock().expect("configuration calls"),
        [(path.to_path_buf(), MAXIMUM_CORE_CLI_CONFIGURATION_BYTES)]
    );

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/core/li_core_cli_configuration_v4.schema.json");
    let schema: Value =
        serde_json::from_slice(&fs::read(schema_path).expect("configuration schema"))
            .expect("schema JSON");
    assert_eq!(
        schema["$id"],
        "https://letsinfer.ai/schemas/core/li_core_cli_configuration_v4.schema.json"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        CORE_CLI_CONFIGURATION_SCHEMA_NAME
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        CORE_CLI_CONFIGURATION_SCHEMA_VERSION
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["client"]["additionalProperties"],
        false
    );
    assert_eq!(schema["$defs"]["path"]["minLength"], 2);
    assert_eq!(schema["$defs"]["path"]["maxLength"], 4_096);
    assert_eq!(
        schema["$defs"]["path"]["pattern"],
        "^/(?:[^/\\u0000-\\u001f\\u007f]+/)*[^/\\u0000-\\u001f\\u007f]+$"
    );
    assert_eq!(
        schema["$defs"]["path"]["not"]["pattern"],
        "(?:^|/)\\.{1,2}(?:/|$)"
    );
}

// Loads the exact Linux Watchdog health identities without admitting aliases or secret bytes.
#[test]
fn configuration_loader_accepts_closed_watchdog_health_paths() {
    let path = Path::new("/var/lib/letsinfer/li_core_cli_configuration.json");
    let mut fixture = configuration_document(
        Path::new("/var/run/user/501/letsinfer/node.sock"),
        Path::new("/dev/urandom"),
    );
    fixture["pairing"]["watchdog_health"] = json!({
        "authority_certificate_file": "/var/lib/letsinfer/watchdog/authority.crt",
        "controller_certificate_file": "/var/lib/letsinfer/watchdog/controller.crt",
        "controller_private_key_file": "/var/lib/letsinfer/watchdog/controller.key"
    });
    let provider =
        ConfigurationFileMock::new(Ok(safe_configuration_file(configuration_bytes(&fixture))));
    let configuration = CoreCliConfiguration::load(path, unsafe { libc::geteuid() }, &provider)
        .expect("Linux pairing configuration");
    let watchdog = configuration
        .pairing()
        .watchdog_health()
        .expect("Watchdog health identities");
    assert_eq!(
        watchdog.authority_certificate_file(),
        Path::new("/var/lib/letsinfer/watchdog/authority.crt")
    );
    assert_eq!(
        watchdog.controller_certificate_file(),
        Path::new("/var/lib/letsinfer/watchdog/controller.crt")
    );
    assert_eq!(
        watchdog.controller_private_key_file(),
        Path::new("/var/lib/letsinfer/watchdog/controller.key")
    );
}

// Loads one exact paired-main endpoint and rejects every identity or path drift.
#[test]
fn configuration_loader_closes_the_paired_main_endpoint_contract() {
    let path = Path::new("/var/lib/letsinfer/li_core_cli_configuration.json");
    let socket = Path::new("/var/run/user/501/letsinfer/node.sock");
    let entropy = Path::new("/dev/urandom");
    let mut fixture = configuration_document(socket, entropy);
    fixture["remote_main"] = json!({
        "address": "main.local",
        "port": 9_770,
        "server_certificate_sha256": "a".repeat(64),
        "client_certificate_file": "/var/lib/letsinfer/li_child_node.crt",
        "client_private_key_file": "/var/lib/letsinfer/li_node.key"
    });
    let provider =
        ConfigurationFileMock::new(Ok(safe_configuration_file(configuration_bytes(&fixture))));
    let configuration = CoreCliConfiguration::load(path, unsafe { libc::geteuid() }, &provider)
        .expect("paired configuration");
    let remote = configuration.remote_main().expect("paired main");
    assert_eq!(remote.address().as_str(), "main.local");
    assert_eq!(remote.port(), 9_770);
    assert_eq!(remote.server_certificate_sha256(), &digest('a'));
    assert_eq!(
        remote.client_certificate_file(),
        Path::new("/var/lib/letsinfer/li_child_node.crt")
    );
    assert_eq!(
        remote.client_private_key_file(),
        Path::new("/var/lib/letsinfer/li_node.key")
    );

    let mut mutations = Vec::new();
    let mut value = fixture.clone();
    value["remote_main"]["extra"] = json!(true);
    mutations.push(value);
    let mut value = fixture.clone();
    value["remote_main"]["port"] = json!(0);
    mutations.push(value);
    let mut value = fixture.clone();
    value["remote_main"]["server_certificate_sha256"] = json!("not-a-digest");
    mutations.push(value);
    let mut value = fixture.clone();
    value["remote_main"]["client_certificate_file"] = json!("relative.crt");
    mutations.push(value);
    let mut value = fixture.clone();
    value["remote_main"]["client_private_key_file"] =
        value["remote_main"]["client_certificate_file"].clone();
    mutations.push(value);
    let mut value = fixture;
    value["remote_main"]["client_private_key_file"] = value["entropy_source"].clone();
    mutations.push(value);

    for mutation in mutations {
        let provider =
            ConfigurationFileMock::new(Ok(safe_configuration_file(configuration_bytes(&mutation))));
        assert_eq!(
            CoreCliConfiguration::load(path, unsafe { libc::geteuid() }, &provider),
            Err(CoreCliProcessError::ConfigurationUnavailable)
        );
    }
}

// Rejects every schema-identity, shape, path, and allocation-bound mutation at the loader.
#[test]
fn configuration_loader_rejects_closed_document_mutations() {
    let path = Path::new("/var/lib/letsinfer/li_core_cli_configuration.json");
    let fixture = configuration_document(
        Path::new("/var/run/user/501/letsinfer/node.sock"),
        Path::new("/dev/urandom"),
    );
    let mut mutations = Vec::new();

    let mut value = fixture.clone();
    value["extra"] = json!(true);
    mutations.push(value);
    let mut value = fixture.clone();
    value["schema"]["extra"] = json!(true);
    mutations.push(value);
    let mut value = fixture.clone();
    value["client"]["extra"] = json!(true);
    mutations.push(value);
    let mut value = fixture.clone();
    value.as_object_mut().expect("object").remove("client");
    mutations.push(value);
    let mut value = fixture.clone();
    value["schema"]["name"] = json!("li_core_cli_configuration_other");
    mutations.push(value);
    let mut value = fixture.clone();
    value["schema"]["version"] = json!(2);
    mutations.push(value);
    let mut value = fixture.clone();
    value["local_node_socket"] = json!("relative.sock");
    mutations.push(value);
    for invalid_path in [
        "/",
        "/var/../node.sock",
        "/var/./node.sock",
        "/var//node.sock",
        "/var/node.sock/",
        "//var/node.sock",
        "C:/node.sock",
    ] {
        let mut value = fixture.clone();
        value["local_node_socket"] = json!(invalid_path);
        mutations.push(value);
    }
    let mut value = fixture.clone();
    value["entropy_source"] = json!("/dev/\u{7f}random");
    mutations.push(value);
    let mut value = fixture.clone();
    value["entropy_source"] = value["local_node_socket"].clone();
    mutations.push(value);
    let mut value = fixture.clone();
    value.as_object_mut().expect("object").remove("pairing");
    mutations.push(value);
    let mut value = fixture.clone();
    value["pairing"]["extra"] = json!(true);
    mutations.push(value);
    let mut value = fixture.clone();
    value["pairing"]["node_configuration_file"] = json!("relative.json");
    mutations.push(value);
    let mut value = fixture.clone();
    value["pairing"]["node_configuration_file"] = value["local_node_socket"].clone();
    mutations.push(value);
    let mut value = fixture.clone();
    value["pairing"]["installation"]["version"] = json!("not a version");
    mutations.push(value);
    let mut value = fixture.clone();
    value["pairing"]["installation"]["source_identity"] = json!("not-a-digest");
    mutations.push(value);
    let mut value = fixture.clone();
    value["pairing"]["watchdog_health"] = json!({
        "authority_certificate_file": "/var/lib/letsinfer/watchdog/authority.crt",
        "controller_certificate_file": "/var/lib/letsinfer/watchdog/controller.crt",
        "controller_private_key_file": "/var/lib/letsinfer/watchdog/controller.crt"
    });
    mutations.push(value);
    let mut value = fixture.clone();
    value.as_object_mut().expect("object").remove("uninstall");
    mutations.push(value);
    let mut value = fixture.clone();
    value["uninstall"]["extra"] = json!(true);
    mutations.push(value);
    let mut value = fixture.clone();
    value["uninstall"]["launcher_file"] = json!("relative/letsinfer");
    mutations.push(value);
    let mut value = fixture.clone();
    value["uninstall"]["launcher_file"] = value["local_node_socket"].clone();
    mutations.push(value);
    let mut value = fixture.clone();
    value["uninstall"]["privilege_command"] = json!("relative/sudo");
    mutations.push(value);
    let mut value = fixture.clone();
    value["uninstall"]["privilege_command"] = value["uninstall"]["launcher_file"].clone();
    mutations.push(value);
    let mut value = fixture.clone();
    value["client"]["timeout_milliseconds"] = json!(0);
    mutations.push(value);
    let mut value = fixture.clone();
    value["client"]["timeout_milliseconds"] = json!(60_001);
    mutations.push(value);
    let mut value = fixture.clone();
    value["client"]["maximum_response_bytes"] = json!(0);
    mutations.push(value);
    let mut value = fixture;
    value["client"]["maximum_response_bytes"] = json!(1_048_577);
    mutations.push(value);

    for mutation in mutations {
        let provider =
            ConfigurationFileMock::new(Ok(safe_configuration_file(configuration_bytes(&mutation))));
        assert_eq!(
            CoreCliConfiguration::load(path, unsafe { libc::geteuid() }, &provider),
            Err(CoreCliProcessError::ConfigurationUnavailable)
        );
    }

    let provider = ConfigurationFileMock::new(Ok(safe_configuration_file(vec![
        b'x';
        MAXIMUM_CORE_CLI_CONFIGURATION_BYTES
            + 1
    ])));
    assert_eq!(
        CoreCliConfiguration::load(path, unsafe { libc::geteuid() }, &provider),
        Err(CoreCliProcessError::ConfigurationUnavailable)
    );
}

// Rejects unsafe descriptor metadata before parsing any otherwise-valid document.
#[test]
fn configuration_loader_rejects_owner_mode_link_and_file_type_mutations() {
    let path = Path::new("/var/lib/letsinfer/li_core_cli_configuration.json");
    let document = configuration_bytes(&configuration_document(
        Path::new("/var/run/user/501/letsinfer/node.sock"),
        Path::new("/dev/urandom"),
    ));
    let owner = unsafe { libc::geteuid() };
    for file in [
        CoreCliConfigurationFile::new(owner.saturating_add(1), 0o600, 1, true, document.clone()),
        CoreCliConfigurationFile::new(owner, 0o640, 1, true, document.clone()),
        CoreCliConfigurationFile::new(owner, 0o600, 2, true, document.clone()),
        CoreCliConfigurationFile::new(owner, 0o600, 1, false, document.clone()),
    ] {
        let provider = ConfigurationFileMock::new(Ok(file));
        assert_eq!(
            CoreCliConfiguration::load(path, owner, &provider),
            Err(CoreCliProcessError::ConfigurationUnavailable)
        );
    }
}

// Proves the system reader accepts only one owner-only regular inode and never follows a symlink.
#[test]
fn system_configuration_reader_is_owner_only_single_link_and_no_follow() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let configuration_path = root.join("li_core_cli_configuration.json");
    fs::write(
        &configuration_path,
        configuration_bytes(&configuration_document(
            &root.join("node.sock"),
            &root.join("entropy"),
        )),
    )
    .expect("configuration");
    fs::set_permissions(&configuration_path, fs::Permissions::from_mode(0o600))
        .expect("owner-only mode");
    let owner = unsafe { libc::geteuid() };
    CoreCliConfiguration::load(
        &configuration_path,
        owner,
        &li_core_application::SystemCoreCliConfigurationFileProvider,
    )
    .expect("safe system configuration");

    fs::set_permissions(&configuration_path, fs::Permissions::from_mode(0o640))
        .expect("group-readable mode");
    assert_eq!(
        CoreCliConfiguration::load(
            &configuration_path,
            owner,
            &li_core_application::SystemCoreCliConfigurationFileProvider,
        ),
        Err(CoreCliProcessError::ConfigurationUnavailable)
    );
    fs::set_permissions(&configuration_path, fs::Permissions::from_mode(0o600))
        .expect("restored mode");

    let hard_link = root.join("configuration-hard-link.json");
    fs::hard_link(&configuration_path, &hard_link).expect("hard link");
    assert_eq!(
        CoreCliConfiguration::load(
            &configuration_path,
            owner,
            &li_core_application::SystemCoreCliConfigurationFileProvider,
        ),
        Err(CoreCliProcessError::ConfigurationUnavailable)
    );
    fs::remove_file(&hard_link).expect("remove hard link");
    CoreCliConfiguration::load(
        &configuration_path,
        owner,
        &li_core_application::SystemCoreCliConfigurationFileProvider,
    )
    .expect("single link restored");

    let symbolic_link = root.join("configuration-symbolic-link.json");
    symlink(&configuration_path, &symbolic_link).expect("symbolic link");
    assert_eq!(
        CoreCliConfiguration::load(
            &symbolic_link,
            owner,
            &li_core_application::SystemCoreCliConfigurationFileProvider,
        ),
        Err(CoreCliProcessError::ConfigurationUnavailable)
    );
}

// Runs one complete context and Node read through the exact local socket and JSON display path.
#[test]
fn process_executes_real_local_node_read_without_python_or_database_access() {
    let node = local_node();
    let (_directory, socket, entropy, server, requests) = native_fixture(vec![
        NodePrivateResponse::LocalNode(node.clone()),
        NodePrivateResponse::HostInventory(local_host_inventory(&node)),
    ]);
    let configuration = socket
        .parent()
        .expect("socket parent")
        .join("li_core_cli_configuration.json");
    let arguments =
        CoreCliProcessArguments::parse(bootstrap(&configuration, &["node", "info", "--json"]))
            .expect("arguments");
    let provider = fixture_configuration_provider(&socket, &entropy);
    let mut process =
        CoreCliProcess::compose(arguments, unsafe { libc::geteuid() }, &provider).expect("process");
    let mut standard_output = Vec::new();
    let mut standard_error = Vec::new();
    let exit = process.run(&mut standard_output, &mut standard_error);
    server.join().expect("server");
    assert_eq!(exit, CliExitCode::Success);
    assert!(standard_error.is_empty());
    let output = String::from_utf8(standard_output).expect("output");
    assert!(output.contains(node.identity().node_id().as_str()));
    assert!(output.contains("\"role\":\"main\""));
    assert_eq!(
        *requests.lock().expect("requests"),
        [
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadHostInventory
        ]
    );
}

// Fails closed before pairing or uninstall when the configured resident Node is unavailable.
#[test]
fn pairing_and_uninstall_fail_closed_without_a_resident_node() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let socket = root.join("absent-node.sock");
    let entropy = root.join("entropy");
    fs::write(&entropy, vec![0x5a; 96]).expect("entropy");
    fs::set_permissions(&entropy, fs::Permissions::from_mode(0o600)).expect("entropy mode");
    let configuration = root.join("li_core_cli_configuration.json");
    let provider = fixture_configuration_provider(&socket, &entropy);
    for command in [&["node", "add", "--json"][..], &["uninstall"][..]] {
        let arguments =
            CoreCliProcessArguments::parse(bootstrap(&configuration, command)).expect("arguments");
        let mut process = CoreCliProcess::compose(arguments, unsafe { libc::geteuid() }, &provider)
            .expect("process");
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();
        let exit = process.run(&mut standard_output, &mut standard_error);

        assert_eq!(exit, CliExitCode::Failure);
        assert!(standard_output.is_empty());
        let error = String::from_utf8(standard_error).expect("error");
        assert!(!error.is_empty());
        assert!(!error.contains(socket.to_string_lossy().as_ref()));
        assert!(!error.contains(entropy.to_string_lossy().as_ref()));
    }
}

// Runs the installed public symlink through `core/current` into the stable setup configuration.
#[test]
fn installed_public_launcher_supplies_configuration_to_the_immutable_binary() {
    let _process_guard = native_cli_process_test_guard();
    let node = local_node();
    let (directory, socket, entropy, server, requests) = native_fixture(vec![
        NodePrivateResponse::LocalNode(node.clone()),
        NodePrivateResponse::HostInventory(local_host_inventory(&node)),
    ]);
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let letsinfer_home = root.join("letsinfer-home");
    let installation = letsinfer_home
        .join("core/versions/1.2.3")
        .join("a".repeat(64));
    fs::create_dir_all(installation.join("bin")).expect("immutable binary root");
    let binary = installation.join("bin/li_letsinfer");
    fs::copy(env!("CARGO_BIN_EXE_li_letsinfer"), &binary).expect("installed binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o555)).expect("immutable binary mode");
    symlink(&installation, letsinfer_home.join("core/current")).expect("current activation");

    let configuration_root = letsinfer_home.join("configuration");
    fs::create_dir(&configuration_root).expect("configuration root");
    fs::set_permissions(&configuration_root, fs::Permissions::from_mode(0o700))
        .expect("configuration root mode");
    let configuration = configuration_root.join(CORE_CLI_CONFIGURATION_FILENAME);
    fs::write(
        &configuration,
        configuration_bytes(&configuration_document(&socket, &entropy)),
    )
    .expect("CLI configuration");
    fs::set_permissions(&configuration, fs::Permissions::from_mode(0o600))
        .expect("CLI configuration mode");

    let launcher = root.join("letsinfer");
    symlink(
        letsinfer_home.join("core/current/bin/li_letsinfer"),
        &launcher,
    )
    .expect("public launcher");
    let output = Command::new(&launcher)
        .args(["node", "info", "--json"])
        .output()
        .expect("public CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().expect("server");
    assert!(output.stderr.is_empty());
    let output = String::from_utf8(output.stdout).expect("output");
    assert!(output.contains(node.identity().node_id().as_str()));
    assert_eq!(
        *requests.lock().expect("requests"),
        [
            NodePrivateRequest::ReadLocalNode,
            NodePrivateRequest::ReadHostInventory
        ]
    );
}

// Presents public root help and version before setup creates configuration.
#[test]
fn installed_public_launcher_presents_metadata_without_configuration() {
    let _process_guard = native_cli_process_test_guard();
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    let letsinfer_home = root.join("letsinfer-home");
    let installation = letsinfer_home
        .join("core/versions/1.2.3")
        .join("a".repeat(64));
    fs::create_dir_all(installation.join("bin")).expect("immutable binary root");
    let binary = installation.join("bin/li_letsinfer");
    fs::copy(env!("CARGO_BIN_EXE_li_letsinfer"), &binary).expect("installed binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o555)).expect("immutable binary mode");
    symlink(&installation, letsinfer_home.join("core/current")).expect("current activation");
    let launcher = root.join("letsinfer");
    symlink(
        letsinfer_home.join("core/current/bin/li_letsinfer"),
        &launcher,
    )
    .expect("public launcher");

    for (argument, expected) in [
        ("--help", native_cli_root_help()),
        (
            "--version",
            concat!("letsinfer ", env!("CARGO_PKG_VERSION"), "\n"),
        ),
    ] {
        let output = Command::new(&launcher)
            .arg(argument)
            .output()
            .expect("public metadata");
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout).expect("metadata output"),
            expected
        );
    }
    assert!(!letsinfer_home.join("configuration").exists());
}

// Keeps the mandatory audit projection as one fail-closed local Node boundary.
#[test]
fn process_preserves_unavailable_host_and_audit_exit_semantics() {
    for (command, expected_error, attempts_audit) in [(
        &["audit", "verify", "--json"][..],
        "FATAL: The private Node endpoint returned an unexpected response.\n",
        true,
    )] {
        let mut responses = vec![NodePrivateResponse::LocalNode(local_node())];
        if attempts_audit {
            responses.push(NodePrivateResponse::CommandAuditOpened(
                NodeCommandAuditOpenReceipt::new(
                    audit_marker(),
                    NodeCommandAuditOpenDisposition::Opened,
                ),
            ));
            responses.push(NodePrivateResponse::LocalNode(local_node()));
        }
        let (_directory, socket, entropy, server, requests) = native_fixture(responses);
        let configuration = socket
            .parent()
            .expect("socket parent")
            .join("li_core_cli_configuration.json");
        let arguments =
            CoreCliProcessArguments::parse(bootstrap(&configuration, command)).expect("arguments");
        let provider = fixture_configuration_provider(&socket, &entropy);
        let mut process = CoreCliProcess::compose(arguments, unsafe { libc::geteuid() }, &provider)
            .expect("process");
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();
        let exit = process.run(&mut standard_output, &mut standard_error);
        assert_eq!(
            exit,
            CliExitCode::Failure,
            "{}",
            String::from_utf8_lossy(&standard_error)
        );
        server.join().expect("server");
        assert!(standard_output.is_empty());
        let error = String::from_utf8(standard_error).expect("error");
        assert_eq!(error, expected_error);
        assert!(!error.contains(configuration.to_string_lossy().as_ref()));
        assert!(!error.contains(entropy.to_string_lossy().as_ref()));
        let requests = requests.lock().expect("requests");
        assert_eq!(requests[0], NodePrivateRequest::ReadLocalNode);
        if attempts_audit {
            assert_eq!(requests.len(), 3);
            assert!(matches!(
                requests[1],
                NodePrivateRequest::OpenCommandAudit(_)
            ));
            assert_eq!(requests[2], NodePrivateRequest::VerifyAudit);
        } else {
            assert_eq!(requests.len(), 1);
        }
    }
}

// Proves the immutable binary enters the strict bootstrap boundary and returns its stable failure.
#[test]
fn native_binary_rejects_incomplete_bootstrap_without_stdout() {
    let _process_guard = native_cli_process_test_guard();
    let output = Command::new(env!("CARGO_BIN_EXE_li_letsinfer"))
        .arg("--invalid")
        .output()
        .expect("binary");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr"),
        "li_letsinfer: li_letsinfer bootstrap arguments are invalid\n"
    );

    let directory = tempfile::tempdir().expect("temporary directory");
    let configuration = fs::canonicalize(directory.path())
        .expect("canonical directory")
        .join("li_core_cli_configuration.json");
    let secret = "one-time-secret-must-never-escape";
    fs::write(&configuration, format!("{{invalid:{secret}}}")).expect("malformed configuration");
    fs::set_permissions(&configuration, fs::Permissions::from_mode(0o600))
        .expect("owner-only configuration");
    let output = Command::new(env!("CARGO_BIN_EXE_li_letsinfer"))
        .args([
            OsString::from("--configuration"),
            configuration.as_os_str().to_owned(),
            OsString::from("--"),
            OsString::from("status"),
            OsString::from("--json"),
        ])
        .output()
        .expect("binary");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).expect("stderr");
    assert_eq!(
        error,
        "li_letsinfer: li_letsinfer configuration is unavailable\n"
    );
    assert!(!error.contains(secret));
    assert!(!error.contains(configuration.to_string_lossy().as_ref()));
}
