// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode, GatewayHealthError,
    GatewayHealthExchange, GatewayHealthObservation, GatewayHealthProbe,
    GatewayHealthReadinessProvider, GatewayHealthServer, GatewayNativeFile, GatewayNativeFileIo,
    GatewayNativeIoError, GatewayResidentIdentity, SystemGatewayHealthExchange,
};
use serde_json::{json, Value};

// Supplies one owner-only in-memory configuration document.
struct ConfigurationFileIo {
    owner_user_id: u32,
    bytes: Vec<u8>,
}

impl GatewayNativeFileIo for ConfigurationFileIo {
    // Returns one exact safe observation without consulting native configuration state.
    fn read_no_follow(
        &self,
        _path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        if self.bytes.len() > maximum_bytes {
            return Err(GatewayNativeIoError::terminal_before_head("oversized"));
        }
        GatewayNativeFile::new(self.owner_user_id, 0o600, 1, self.bytes.clone())
    }
}

// Builds one strict role-exact configuration around the selected local health path.
fn configuration(socket_path: &Path, mode: &str, owner_user_id: u32) -> GatewayConfiguration {
    let mut document = json!({
        "schema": {"name": "li_gateway_configuration", "version": 5},
        "node_id": "11111111111111111111111111111111",
        "core_release": "1.2.3",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "mode": mode,
        "health": {
            "socket_path": socket_path,
            "maximum_workers": 4,
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "accept_poll_interval_milliseconds": 5
        },
        "node_protection": {
            "socket_path": "/private/node_protection.sock",
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "maximum_cache_milliseconds": 2000,
            "poll_interval_milliseconds": 500
        },
        "runtime": {
            "node_socket_path": "/private/node.sock",
            "telemetry_file": "/private/gateway_telemetry_v2",
            "telemetry_cadence_milliseconds": 1000,
            "maximum_queue_milliseconds": 30000
        },
        "private_listener": {
            "address": "127.0.0.1:9444",
            "maximum_connections": 8,
            "tls": {
                "server_certificate_file": "/private/gateway.crt",
                "server_private_key_file": "/private/gateway.key",
                "client_ca_file": "/private/main-ca.crt",
                "client_certificate_file": "/private/main.crt"
            }
        }
    });
    if mode == "main" {
        document.as_object_mut().expect("object").insert(
            "public_listener".to_string(),
            json!({"address": "127.0.0.1:8080", "maximum_connections": 8}),
        );
    }
    let bytes = serde_json::to_vec(&document).expect("configuration JSON");
    GatewayConfiguration::load(
        &GatewayConfigurationFile::new(owner_user_id, PathBuf::from("/configuration.json"))
            .expect("configuration reference"),
        &ConfigurationFileIo {
            owner_user_id,
            bytes,
        },
    )
    .expect("configuration")
}

// Selects one deterministic response mutation at the injected transport boundary.
#[derive(Clone, Copy)]
enum ResponseMutation {
    ExactReady,
    ExactNotReady,
    WrongRequest,
    WrongNode,
    WrongMode,
    WrongRelease,
    WrongSource,
    UnknownReadiness,
    Malformed,
    Truncated,
    Oversized,
    Failure(GatewayHealthError),
}

// Produces protocol-shaped responses without mocking the probe's judgment.
struct ExchangeMock {
    mutation: ResponseMutation,
    calls: Mutex<Vec<Duration>>,
}

impl GatewayHealthExchange for ExchangeMock {
    // Returns one selected response while preserving the probe-generated request identity.
    fn exchange(
        &self,
        _configuration: &li_gateway_manager::GatewayHealthConfiguration,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, GatewayHealthError> {
        self.calls.lock().expect("calls").push(timeout);
        if let ResponseMutation::Failure(error) = self.mutation {
            return Err(error);
        }
        if matches!(self.mutation, ResponseMutation::Malformed) {
            return Ok(b"not-json".to_vec());
        }
        if matches!(self.mutation, ResponseMutation::Truncated) {
            return Ok(br#"{"schema":{"name":"li_gateway_health""#.to_vec());
        }
        if matches!(self.mutation, ResponseMutation::Oversized) {
            return Ok(vec![b' '; 4 * 1024 + 1]);
        }
        let request: Value = serde_json::from_slice(request).expect("request");
        let mut response = json!({
            "schema": {"name": "li_gateway_health", "version": 1},
            "request_id": request["request_id"],
            "node_id": "11111111111111111111111111111111",
            "mode": "main",
            "core_release": "1.2.3",
            "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "readiness": if matches!(self.mutation, ResponseMutation::ExactNotReady) {
                "not_ready"
            } else {
                "ready"
            }
        });
        match self.mutation {
            ResponseMutation::WrongRequest => response["request_id"] = Value::from("f".repeat(64)),
            ResponseMutation::WrongNode => response["node_id"] = Value::from("2".repeat(32)),
            ResponseMutation::WrongMode => response["mode"] = Value::from("child"),
            ResponseMutation::WrongRelease => response["core_release"] = Value::from("1.2.4"),
            ResponseMutation::WrongSource => {
                response["core_source_identity"] = Value::from("d".repeat(64));
            }
            ResponseMutation::UnknownReadiness => {
                response["readiness"] = Value::from("warming");
            }
            _ => {}
        }
        serde_json::to_vec(&response).map_err(|_| GatewayHealthError::InvalidResponse)
    }
}

// Observes one selected injected response through the production probe.
fn observe_mutation(
    mutation: ResponseMutation,
) -> Result<GatewayHealthObservation, GatewayHealthError> {
    let exchange = Arc::new(ExchangeMock {
        mutation,
        calls: Mutex::new(Vec::new()),
    });
    GatewayHealthProbe::new(exchange).observe(
        &configuration(Path::new("/private/gateway.sock"), "main", 501),
        Duration::from_millis(917),
    )
}

// Proves exact ready and not-ready responses retain distinct setup semantics.
#[test]
fn probe_accepts_only_exact_identity_bound_readiness() {
    assert_eq!(
        observe_mutation(ResponseMutation::ExactReady),
        Ok(GatewayHealthObservation::Ready)
    );
    assert_eq!(
        observe_mutation(ResponseMutation::ExactNotReady),
        Ok(GatewayHealthObservation::NotReady)
    );
}

// Rejects every correlation, identity, mode, release, source, and readiness mutation.
#[test]
fn probe_identity_and_status_mutation_matrix_fails_closed() {
    for mutation in [
        ResponseMutation::WrongRequest,
        ResponseMutation::WrongNode,
        ResponseMutation::WrongMode,
        ResponseMutation::WrongRelease,
        ResponseMutation::WrongSource,
        ResponseMutation::UnknownReadiness,
    ] {
        assert_eq!(
            observe_mutation(mutation),
            Err(GatewayHealthError::InvalidResponse)
        );
    }
}

// Rejects malformed, truncated, oversized, timed-out, and unavailable response boundaries.
#[test]
fn probe_transport_and_document_failure_matrix_is_redacted() {
    for (mutation, expected) in [
        (
            ResponseMutation::Malformed,
            GatewayHealthError::InvalidResponse,
        ),
        (
            ResponseMutation::Truncated,
            GatewayHealthError::InvalidResponse,
        ),
        (
            ResponseMutation::Oversized,
            GatewayHealthError::InvalidResponse,
        ),
        (
            ResponseMutation::Failure(GatewayHealthError::DeadlineExceeded),
            GatewayHealthError::DeadlineExceeded,
        ),
        (
            ResponseMutation::Failure(GatewayHealthError::AuthenticationUnavailable),
            GatewayHealthError::AuthenticationUnavailable,
        ),
        (
            ResponseMutation::Failure(GatewayHealthError::EndpointUnavailable),
            GatewayHealthError::EndpointUnavailable,
        ),
    ] {
        assert_eq!(observe_mutation(mutation), Err(expected));
    }
    let probe = GatewayHealthProbe::new(Arc::new(ExchangeMock {
        mutation: ResponseMutation::ExactReady,
        calls: Mutex::new(Vec::new()),
    }));
    assert_eq!(
        probe.observe(
            &configuration(Path::new("/private/gateway.sock"), "main", 501),
            Duration::ZERO,
        ),
        Err(GatewayHealthError::InvalidContract)
    );
}

// Supplies mutable deterministic telemetry readiness to a real local health server.
struct Readiness(AtomicBool);

impl GatewayHealthReadinessProvider for Readiness {
    // Returns the current deterministic readiness value without native state.
    fn is_ready(&self) -> Result<bool, GatewayHealthError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

// Creates one private temporary directory acceptable to the production server.
fn private_directory() -> tempfile::TempDir {
    let root = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    let directory = tempfile::tempdir_in(root).expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    directory
}

// Proves both modes use the same local endpoint and readiness follows fresh telemetry state.
#[test]
fn real_server_serves_main_and_child_and_tracks_fresh_readiness() {
    for mode in ["main", "child"] {
        let directory = private_directory();
        let configuration = configuration(
            &directory.path().join("gateway_health.sock"),
            mode,
            effective_user_id(),
        );
        let readiness = Arc::new(Readiness(AtomicBool::new(false)));
        let server = GatewayHealthServer::start(
            configuration.health().clone(),
            GatewayResidentIdentity::from_configuration(&configuration),
            readiness.clone(),
        )
        .expect("server");
        let probe = GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange));
        assert_eq!(
            probe.observe(&configuration, Duration::from_secs(1)),
            Ok(GatewayHealthObservation::NotReady)
        );
        readiness.0.store(true, Ordering::SeqCst);
        assert_eq!(
            probe.observe(&configuration, Duration::from_secs(1)),
            Ok(GatewayHealthObservation::Ready)
        );
        assert_eq!(
            configuration.mode(),
            if mode == "main" {
                GatewayConfigurationMode::Main
            } else {
                GatewayConfigurationMode::Child
            }
        );
        server.join().expect("join");
        assert!(!configuration.health().socket_path().exists());
    }
}

// Proves stop interrupts a stalled peer and join owns every worker plus socket cleanup.
#[test]
fn real_server_shutdown_interrupts_stalled_connection_and_joins() {
    let directory = private_directory();
    let configuration = configuration(
        &directory.path().join("gateway_health.sock"),
        "main",
        effective_user_id(),
    );
    let server = GatewayHealthServer::start(
        configuration.health().clone(),
        GatewayResidentIdentity::from_configuration(&configuration),
        Arc::new(Readiness(AtomicBool::new(true))),
    )
    .expect("server");
    let mut stalled = UnixStream::connect(configuration.health().socket_path()).expect("connect");
    thread::sleep(Duration::from_millis(20));
    let started = Instant::now();
    server.join().expect("join");
    assert!(started.elapsed() < Duration::from_secs(1));
    let mut byte = [0_u8; 1];
    assert_eq!(stalled.read(&mut byte).expect("closed stream"), 0);
    server.join().expect("replayed join");
}

// Keeps unsafe preexisting files intact and rejects owner, mode, link, and symlink hazards.
#[test]
fn native_socket_metadata_safety_matrix_never_replaces_foreign_state() {
    let directory = private_directory();
    let socket_path = directory.path().join("gateway_health.sock");
    fs::write(&socket_path, b"foreign").expect("foreign file");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("mode");
    let valid_configuration = configuration(&socket_path, "main", effective_user_id());
    assert!(GatewayHealthServer::start(
        valid_configuration.health().clone(),
        GatewayResidentIdentity::from_configuration(&valid_configuration),
        Arc::new(Readiness(AtomicBool::new(true))),
    )
    .is_err());
    assert_eq!(fs::read(&socket_path).expect("foreign bytes"), b"foreign");

    fs::remove_file(&socket_path).expect("remove fixture");
    let listener = UnixListener::bind(&socket_path).expect("listener");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)).expect("unsafe mode");
    assert_eq!(
        GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange))
            .observe(&valid_configuration, Duration::from_millis(100),),
        Err(GatewayHealthError::AuthenticationUnavailable)
    );
    drop(listener);
    fs::remove_file(&socket_path).expect("remove listener");

    let target = directory.path().join("target.sock");
    let target_listener = UnixListener::bind(&target).expect("target listener");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    std::os::unix::fs::symlink(&target, &socket_path).expect("socket symlink");
    assert_eq!(
        GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange))
            .observe(&valid_configuration, Duration::from_millis(100),),
        Err(GatewayHealthError::AuthenticationUnavailable)
    );
    fs::remove_file(&socket_path).expect("remove symlink");
    drop(target_listener);
    fs::remove_file(&target).expect("remove target");

    let linked_listener = UnixListener::bind(&socket_path).expect("linked listener");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("linked mode");
    let link = directory.path().join("gateway_health.link");
    fs::hard_link(&socket_path, &link).expect("socket hard link");
    assert_eq!(
        GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange))
            .observe(&valid_configuration, Duration::from_millis(100),),
        Err(GatewayHealthError::AuthenticationUnavailable)
    );
    drop(linked_listener);
    fs::remove_file(&link).expect("remove link");
    fs::remove_file(&socket_path).expect("remove socket");

    let wrong_owner = configuration(&socket_path, "main", effective_user_id() + 1);
    let wrong_owner_listener = UnixListener::bind(&socket_path).expect("wrong-owner listener");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("wrong-owner mode");
    assert_eq!(
        GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange))
            .observe(&wrong_owner, Duration::from_millis(100)),
        Err(GatewayHealthError::AuthenticationUnavailable)
    );
    drop(wrong_owner_listener);
    fs::remove_file(&socket_path).expect("remove wrong-owner socket");
    assert!(GatewayHealthServer::start(
        wrong_owner.health().clone(),
        GatewayResidentIdentity::from_configuration(&wrong_owner),
        Arc::new(Readiness(AtomicBool::new(true))),
    )
    .is_err());

    let real_parent = directory.path().join("real_parent");
    fs::create_dir(&real_parent).expect("real parent");
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).expect("parent mode");
    let linked_parent = directory.path().join("linked_parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("parent symlink");
    let linked_socket = linked_parent.join("gateway_health.sock");
    let intermediate_listener =
        UnixListener::bind(real_parent.join("gateway_health.sock")).expect("intermediate listener");
    fs::set_permissions(
        real_parent.join("gateway_health.sock"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("intermediate socket mode");
    let intermediate_configuration = configuration(&linked_socket, "main", effective_user_id());
    assert_eq!(
        GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange))
            .observe(&intermediate_configuration, Duration::from_millis(100),),
        Err(GatewayHealthError::AuthenticationUnavailable)
    );
    assert!(GatewayHealthServer::start(
        intermediate_configuration.health().clone(),
        GatewayResidentIdentity::from_configuration(&intermediate_configuration),
        Arc::new(Readiness(AtomicBool::new(true))),
    )
    .is_err());
    drop(intermediate_listener);
}

// Selects one hostile but owner-local response framing behavior.
#[derive(Clone, Copy)]
enum RawServerBehavior {
    Truncated,
    Oversized,
    Stall,
    ReplaceSocket,
}

// Starts one raw owner-local server for native client boundary tests.
fn start_raw_server(socket_path: PathBuf, behavior: RawServerBehavior) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(&socket_path).expect("raw listener");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("raw mode");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("raw accept");
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).expect("request header");
        let length = u32::from_be_bytes(header) as usize;
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).expect("request body");
        match behavior {
            RawServerBehavior::Truncated => {
                stream.write_all(&32_u32.to_be_bytes()).expect("header");
                stream.write_all(b"{}").expect("truncated body");
            }
            RawServerBehavior::Oversized => {
                stream.write_all(&4097_u32.to_be_bytes()).expect("header");
            }
            RawServerBehavior::Stall => thread::sleep(Duration::from_millis(200)),
            RawServerBehavior::ReplaceSocket => {
                fs::remove_file(&socket_path).expect("remove original socket");
                let replacement = UnixListener::bind(&socket_path).expect("replacement");
                fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
                let request: Value = serde_json::from_slice(&request).expect("request JSON");
                let response = serde_json::to_vec(&json!({
                    "schema": {"name": "li_gateway_health", "version": 1},
                    "request_id": request["request_id"],
                    "node_id": "11111111111111111111111111111111",
                    "mode": "main",
                    "core_release": "1.2.3",
                    "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "readiness": "ready"
                }))
                .expect("response");
                stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .and_then(|()| stream.write_all(&response))
                    .expect("response frame");
                drop(replacement);
            }
        }
    })
}

// Rejects native truncation, oversized frames, stalls, and path replacement under one deadline.
#[test]
fn native_exchange_deadline_framing_and_path_stability_fail_closed() {
    for (behavior, expected) in [
        (
            RawServerBehavior::Truncated,
            GatewayHealthError::InvalidResponse,
        ),
        (
            RawServerBehavior::Oversized,
            GatewayHealthError::InvalidResponse,
        ),
        (
            RawServerBehavior::Stall,
            GatewayHealthError::DeadlineExceeded,
        ),
        (
            RawServerBehavior::ReplaceSocket,
            GatewayHealthError::AuthenticationUnavailable,
        ),
    ] {
        let directory = private_directory();
        let socket_path = directory.path().join("gateway_health.sock");
        let server = start_raw_server(socket_path.clone(), behavior);
        let configuration = configuration(&socket_path, "main", effective_user_id());
        let timeout = if matches!(behavior, RawServerBehavior::Stall) {
            Duration::from_millis(30)
        } else {
            Duration::from_secs(1)
        };
        assert_eq!(
            GatewayHealthProbe::new(Arc::new(SystemGatewayHealthExchange))
                .observe(&configuration, timeout),
            Err(expected)
        );
        server.join().expect("raw server");
    }
}

// Returns the effective account identity used by the native test process.
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process identity.
    unsafe { libc::geteuid() }
}
