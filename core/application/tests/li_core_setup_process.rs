// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_application::{
    decode_core_setup_input, run_core_setup_process, ApplicationCoreSetup,
    CoreSetupCompositionError, CoreSetupError, CoreSetupPersistencePreflight,
    CoreSetupProcessApplicationRunner, CoreSetupProcessError, CoreSetupProcessIo,
    CoreSetupStoreError, CoreSetupWatchdogCapabilityError, CoreSetupWatchdogCapabilityPreflight,
    DecodedCoreSetupInput, CORE_SETUP_EXIT_COMMITTED, CORE_SETUP_EXIT_RECOVERY_REQUIRED,
    CORE_SETUP_EXIT_SAFE_TO_ROLLBACK, MAXIMUM_CORE_SETUP_INPUT_BYTES,
};
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use serde_json::{json, Value};
use tempfile::TempDir;

// Stores exact application outcomes and records every process-boundary invocation.
struct TestApplicationRunner {
    outcomes: Mutex<VecDeque<Result<Vec<u8>, CoreSetupCompositionError>>>,
    invocations: AtomicUsize,
    contexts: Mutex<Vec<CoreUpdateServiceContext>>,
}

impl TestApplicationRunner {
    // Creates one deterministic runner with an exact ordered outcome sequence.
    fn new(outcomes: Vec<Result<Vec<u8>, CoreSetupCompositionError>>) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from(outcomes)),
            invocations: AtomicUsize::new(0),
            contexts: Mutex::new(Vec::new()),
        }
    }

    // Returns how many validated inputs crossed the application boundary.
    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    // Returns every exact request context observed by the application seam.
    fn contexts(&self) -> Vec<CoreUpdateServiceContext> {
        self.contexts.lock().expect("contexts").clone()
    }
}

impl CoreSetupProcessApplicationRunner for TestApplicationRunner {
    // Records the validated request and returns the next injected application outcome.
    fn setup_json(
        &self,
        input: DecodedCoreSetupInput,
    ) -> Result<Vec<u8>, CoreSetupCompositionError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.contexts
            .lock()
            .expect("contexts")
            .push(input.request().context());
        self.outcomes
            .lock()
            .expect("outcomes")
            .pop_front()
            .expect("injected application outcome")
    }
}

// Captures one deterministic standard-stream exchange without native file descriptors.
struct TestProcessIo {
    input: Result<Vec<u8>, CoreSetupProcessError>,
    output: Vec<u8>,
    error: Vec<u8>,
    reject_output: bool,
}

impl TestProcessIo {
    // Creates one readable process exchange from exact input bytes.
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Ok(input),
            output: Vec::new(),
            error: Vec::new(),
            reject_output: false,
        }
    }

    // Creates one exchange whose stdin read fails before decoding.
    fn unavailable_input() -> Self {
        Self {
            input: Err(CoreSetupProcessError::InputUnavailable),
            output: Vec::new(),
            error: Vec::new(),
            reject_output: false,
        }
    }
}

impl CoreSetupProcessIo for TestProcessIo {
    // Returns the exact injected bytes or stable read failure.
    fn read_input(&mut self, _maximum_bytes: usize) -> Result<Vec<u8>, CoreSetupProcessError> {
        self.input.clone()
    }

    // Captures the exact successful result unless output failure was injected.
    fn write_output(&mut self, bytes: &[u8]) -> Result<(), CoreSetupProcessError> {
        if self.reject_output {
            return Err(CoreSetupProcessError::OutputUnavailable);
        }
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    // Captures the stable redacted error line.
    fn write_error(&mut self, bytes: &[u8]) -> Result<(), CoreSetupProcessError> {
        self.error.extend_from_slice(bytes);
        Ok(())
    }
}

// Accepts persistence capability without invoking the native service manager.
struct AcceptingPersistencePreflight;

impl CoreSetupPersistencePreflight for AcceptingPersistencePreflight {
    // Accepts one already-decoded platform and effective owner.
    fn verify(
        &self,
        _context: CoreUpdateServiceContext,
        _owner_user_id: u32,
    ) -> Result<(), CoreSetupCompositionError> {
        Ok(())
    }
}

// Accepts one positive Watchdog capability without loading a native NVML provider.
struct AcceptingWatchdogCapabilityPreflight;

impl CoreSetupWatchdogCapabilityPreflight for AcceptingWatchdogCapabilityPreflight {
    // Returns one physical GPU for either decoded platform fixture.
    fn physical_device_count(&self) -> Result<Option<u32>, CoreSetupWatchdogCapabilityError> {
        Ok(Some(1))
    }
}

// Proves both wire variants decode into the complete production composition graph.
#[test]
fn decoder_constructs_linux_and_macos_production_compositions() {
    for platform in [
        CoreUpdateServicePlatform::Linux,
        CoreUpdateServicePlatform::Macos,
    ] {
        let temporary = private_temporary();
        let document = input_document(platform, &temporary);
        let decoded = decode_core_setup_input(&encoded(&document)).expect("decoded input");
        assert_eq!(
            decoded.request().context(),
            CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main)
        );
        let (composition, _request) = decoded.into_parts();
        let application = ApplicationCoreSetup::compose_with_preflights(
            composition,
            Arc::new(AcceptingPersistencePreflight),
            Arc::new(AcceptingWatchdogCapabilityPreflight),
        )
        .expect("production composition");
        assert_eq!(
            application.context(),
            CoreUpdateServiceContext::new(platform, CoreUpdateNodeRole::Main)
        );
    }
}

// Preserves installed and replayed results as the only exact stdout documents.
#[test]
fn process_writes_only_newline_terminated_setup_results() {
    let temporary = private_temporary();
    let input = encoded(&input_document(
        CoreUpdateServicePlatform::Linux,
        &temporary,
    ));
    for disposition in ["installed", "replayed"] {
        let result = result_document(disposition, CoreUpdateServicePlatform::Linux);
        let runner = TestApplicationRunner::new(vec![Ok(result.clone())]);
        let mut io = TestProcessIo::new(input.clone());
        assert_eq!(
            run_core_setup_process(&arguments(), &mut io, &runner),
            CORE_SETUP_EXIT_COMMITTED
        );
        assert_eq!(io.output, result);
        assert!(io.error.is_empty());
        assert_eq!(runner.invocations(), 1);
        assert_eq!(
            runner.contexts(),
            vec![CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Linux,
                CoreUpdateNodeRole::Main,
            )]
        );
    }
}

// Maps ambiguous application, stdin, and stdout failures onto recovery-required status.
#[test]
fn process_maps_application_and_stream_failures_without_mixed_output() {
    let temporary = private_temporary();
    let input = encoded(&input_document(
        CoreUpdateServicePlatform::Macos,
        &temporary,
    ));
    let runner =
        TestApplicationRunner::new(vec![Err(CoreSetupCompositionError::DatabaseUnavailable)]);
    let mut setup_failure = TestProcessIo::new(input.clone());
    assert_eq!(
        run_core_setup_process(&arguments(), &mut setup_failure, &runner),
        CORE_SETUP_EXIT_RECOVERY_REQUIRED
    );
    assert!(setup_failure.output.is_empty());
    assert_eq!(setup_failure.error, b"Core database is unavailable\n");

    let runner = TestApplicationRunner::new(Vec::new());
    let mut input_failure = TestProcessIo::unavailable_input();
    assert_eq!(
        run_core_setup_process(&arguments(), &mut input_failure, &runner),
        CORE_SETUP_EXIT_RECOVERY_REQUIRED
    );
    assert!(input_failure.output.is_empty());
    assert_eq!(input_failure.error, b"li_core_setup input is unavailable\n");
    assert_eq!(runner.invocations(), 0);

    let runner = TestApplicationRunner::new(vec![Ok(result_document(
        "installed",
        CoreUpdateServicePlatform::Macos,
    ))]);
    let mut output_failure = TestProcessIo::new(input);
    output_failure.reject_output = true;
    assert_eq!(
        run_core_setup_process(&arguments(), &mut output_failure, &runner),
        CORE_SETUP_EXIT_RECOVERY_REQUIRED
    );
    assert!(output_failure.output.is_empty());
    assert_eq!(
        output_failure.error,
        b"li_core_setup output is unavailable\n"
    );
}

// Authorizes installer rollback only after Core reports exact durable compensation.
#[test]
fn process_maps_a_rolled_back_transaction_onto_the_safe_exit_class() {
    let temporary = private_temporary();
    let input = encoded(&input_document(
        CoreUpdateServicePlatform::Macos,
        &temporary,
    ));
    let runner = TestApplicationRunner::new(vec![Err(CoreSetupCompositionError::Setup(
        CoreSetupError::RolledBack {
            capability: "resident services",
            reason: "injected compensated failure",
        },
    ))]);
    let mut io = TestProcessIo::new(input);

    assert_eq!(
        run_core_setup_process(&arguments(), &mut io, &runner),
        CORE_SETUP_EXIT_SAFE_TO_ROLLBACK
    );
    assert!(io.output.is_empty());
    assert_eq!(
        io.error,
        b"Core setup resident services rolled back: injected compensated failure\n"
    );
    assert_eq!(runner.invocations(), 1);
}

// Keeps every non-compensated composition and setup failure in the recovery-required class.
#[test]
fn process_never_authorizes_rollback_for_an_ambiguous_application_failure() {
    let cases = [
        (
            "invalid_composition",
            CoreSetupCompositionError::InvalidContract {
                reason: "injected invalid composition",
            },
        ),
        (
            "setup_state",
            CoreSetupCompositionError::SetupStateUnavailable,
        ),
        ("database", CoreSetupCompositionError::DatabaseUnavailable),
        ("material", CoreSetupCompositionError::MaterialUnavailable),
        (
            "boot_persistence",
            CoreSetupCompositionError::BootPersistenceUnavailable,
        ),
        (
            "watchdog_capability",
            CoreSetupCompositionError::WatchdogCapabilityUnavailable,
        ),
        (
            "resident_services",
            CoreSetupCompositionError::ResidentServicesUnavailable,
        ),
        (
            "invalid_setup_contract",
            CoreSetupCompositionError::Setup(CoreSetupError::InvalidContract {
                reason: "injected invalid setup",
            }),
        ),
        (
            "busy",
            CoreSetupCompositionError::Setup(CoreSetupError::Busy),
        ),
        (
            "idempotency_conflict",
            CoreSetupCompositionError::Setup(CoreSetupError::IdempotencyConflict),
        ),
        (
            "store",
            CoreSetupCompositionError::Setup(CoreSetupError::Store(
                CoreSetupStoreError::Unavailable,
            )),
        ),
        (
            "provider",
            CoreSetupCompositionError::Setup(CoreSetupError::Provider {
                capability: "resident services",
                reason: "injected provider failure",
            }),
        ),
        (
            "recovery",
            CoreSetupCompositionError::Setup(CoreSetupError::RecoveryRequired {
                capability: "resident services",
                reason: "injected recovery failure",
            }),
        ),
    ];

    for (name, error) in cases {
        let temporary = private_temporary();
        let input = encoded(&input_document(
            CoreUpdateServicePlatform::Linux,
            &temporary,
        ));
        let runner = TestApplicationRunner::new(vec![Err(error)]);
        let mut io = TestProcessIo::new(input);

        assert_eq!(
            run_core_setup_process(&arguments(), &mut io, &runner),
            CORE_SETUP_EXIT_RECOVERY_REQUIRED,
            "{name}"
        );
        assert!(io.output.is_empty(), "{name}");
        assert!(!io.error.is_empty(), "{name}");
        assert_eq!(runner.invocations(), 1, "{name}");
    }
}

// Rejects malformed framing, encoding, schema, role, platform, and paths before application work.
#[test]
fn process_rejects_invalid_documents_before_the_application_runner() {
    let temporary = private_temporary();
    let valid = input_document(CoreUpdateServicePlatform::Linux, &temporary);
    let mut cases = vec![
        ("empty", Vec::new()),
        ("non_utf8", vec![0xff, 0xfe]),
        ("truncated", b"{\"schema\":".to_vec()),
        ("oversized", vec![b' '; MAXIMUM_CORE_SETUP_INPUT_BYTES + 1]),
    ];
    let mut extra = encoded(&valid);
    extra.extend_from_slice(b"\n{}");
    cases.push(("extra_document", extra));
    for (name, value) in invalid_documents(valid) {
        cases.push((name, encoded(&value)));
    }
    for (name, bytes) in cases {
        let runner = TestApplicationRunner::new(Vec::new());
        let mut io = TestProcessIo::new(bytes);
        assert_eq!(
            run_core_setup_process(&arguments(), &mut io, &runner),
            CORE_SETUP_EXIT_SAFE_TO_ROLLBACK,
            "{name}"
        );
        assert!(io.output.is_empty(), "{name}");
        assert_eq!(io.error, b"li_core_setup input is invalid\n", "{name}");
        assert_eq!(runner.invocations(), 0, "{name}");
    }
}

// Rejects every optional argv surface before reading or dispatching the setup document.
#[test]
fn process_rejects_command_arguments_before_application_work() {
    let runner = TestApplicationRunner::new(Vec::new());
    let mut io = TestProcessIo::new(Vec::new());
    let arguments = [OsString::from("li_core_setup"), OsString::from("--json")];
    assert_eq!(
        run_core_setup_process(&arguments, &mut io, &runner),
        CORE_SETUP_EXIT_SAFE_TO_ROLLBACK
    );
    assert!(io.output.is_empty());
    assert_eq!(io.error, b"li_core_setup arguments are invalid\n");
    assert_eq!(runner.invocations(), 0);
}

// Accepts disabled and maximum queueing while rejecting the first out-of-range value.
#[test]
fn decoder_matches_the_gateway_queue_contract() {
    for maximum_queue_milliseconds in [0_u64, 300_000] {
        let temporary = private_temporary();
        let mut document = input_document(CoreUpdateServicePlatform::Macos, &temporary);
        document["configuration"]["gateway"]["maximum_queue_milliseconds"] =
            Value::from(maximum_queue_milliseconds);
        assert!(decode_core_setup_input(&encoded(&document)).is_ok());
    }
    let temporary = private_temporary();
    let mut document = input_document(CoreUpdateServicePlatform::Macos, &temporary);
    document["configuration"]["gateway"]["maximum_queue_milliseconds"] = Value::from(300_001);
    assert_eq!(
        decode_core_setup_input(&encoded(&document)).err(),
        Some(CoreSetupProcessError::InvalidInput)
    );
}

// Keeps schema ownership and queue bounds aligned with the Rust decoder.
#[test]
fn input_schema_matches_the_closed_process_contract() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/core/li_core_setup_input_v5.schema.json"
    ))
    .expect("input schema");
    let node = &schema["$defs"]["node_configuration"];
    let native_variants = schema["$defs"]["native"]["oneOf"]
        .as_array()
        .expect("native variants");
    assert!(node["properties"].get("openssl_command").is_none());
    assert!(native_variants
        .iter()
        .all(|variant| variant["properties"].get("openssl_command").is_some()));
    assert_eq!(
        schema["$defs"]["gateway_configuration"]["properties"]["maximum_queue_milliseconds"]
            ["minimum"],
        0
    );
    assert_eq!(
        schema["$defs"]["gateway_configuration"]["properties"]["maximum_queue_milliseconds"]
            ["maximum"],
        300_000
    );
    assert_eq!(
        schema["$defs"]["cli_configuration"]["properties"]["timeout_milliseconds"]["maximum"],
        60_000
    );
    assert_eq!(
        schema["$defs"]["cli_configuration"]["properties"]["maximum_response_bytes"]["maximum"],
        1_048_576
    );
    assert_eq!(
        schema["$defs"]["node_model_configuration"]["properties"]["catalog_source"]["pattern"],
        "^https://[^\\s@#/]+(?:/[^\\s@#]*)*/catalog\\.json$"
    );
}

// Produces every semantic or structural mutation that must fail before composition.
fn invalid_documents(valid: Value) -> Vec<(&'static str, Value)> {
    let mut cases = Vec::new();
    let mut unknown = valid.clone();
    unknown["unexpected"] = Value::Bool(true);
    cases.push(("unknown_field", unknown));
    let mut schema_name = valid.clone();
    schema_name["schema"]["name"] = Value::from("li_other_input");
    cases.push(("schema_name", schema_name));
    let mut schema_version = valid.clone();
    schema_version["schema"]["version"] = Value::from(1);
    cases.push(("schema_version", schema_version));
    let mut child = valid.clone();
    child["request"]["role"] = Value::from("child");
    cases.push(("child_role", child));
    let mut platform = valid.clone();
    platform["request"]["platform"] = Value::from("macos");
    cases.push(("platform_substitution", platform));
    let mut path = valid.clone();
    path["roots"]["material_root"] = Value::from("/tmp/../material");
    cases.push(("unsafe_path", path));
    let mut control_path = valid.clone();
    control_path["roots"]["material_root"] = Value::from("/tmp/material\nunsafe");
    cases.push(("control_path", control_path));
    let mut escaped_material = valid.clone();
    escaped_material["material"]["gateway"]["server_private_key_file"] =
        Value::from("/tmp/escaped.key");
    cases.push(("escaped_material", escaped_material));
    let mut health = valid.clone();
    health["native"]["watchdog_health"]["controller_private_key_file"] =
        Value::from("/tmp/mismatched.key");
    cases.push(("watchdog_binding", health));
    let mut openssl = valid.clone();
    openssl["native"]["openssl_command"] = Value::from("/usr/bin/curl");
    cases.push(("native_tool_substitution", openssl));
    let mut old_openssl_owner = valid.clone();
    old_openssl_owner["configuration"]["node"]["openssl_command"] = Value::from("/usr/bin/openssl");
    cases.push(("old_openssl_owner", old_openssl_owner));
    let mut pairing_workspace = valid.clone();
    pairing_workspace["configuration"]["node"]["trust_workspace"] =
        Value::from("/var/lib/letsinfer/other/pairing_trust_staging");
    cases.push(("pairing_workspace", pairing_workspace));
    let mut runtime_catalog = valid.clone();
    runtime_catalog["configuration"]["node"]["model"]["catalog_source"] =
        Value::from("https://catalog.letsinfer.ai/release.json");
    cases.push(("runtime_catalog", runtime_catalog));
    let mut queue = valid.clone();
    queue["configuration"]["gateway"]["maximum_queue_milliseconds"] = Value::from(300_001);
    cases.push(("queue_bound", queue));
    let mut duplicate_listener = valid.clone();
    duplicate_listener["request"]["gateway_private_address"] = Value::from("0.0.0.0:9443");
    cases.push(("duplicate_listener_port", duplicate_listener));
    for (name, section, field, value) in [
        (
            "node_cadence_lower",
            "node",
            "daemon_cadence_milliseconds",
            99_u64,
        ),
        (
            "node_cadence_upper",
            "node",
            "daemon_cadence_milliseconds",
            300_001,
        ),
        ("node_workers", "node", "remote_maximum_workers", 65),
        (
            "node_accept_poll",
            "node",
            "remote_accept_poll_interval_milliseconds",
            1_001,
        ),
        (
            "node_timeout",
            "node",
            "remote_handshake_timeout_milliseconds",
            60_001,
        ),
        (
            "gateway_telemetry_lower",
            "gateway",
            "telemetry_cadence_milliseconds",
            99,
        ),
        (
            "gateway_telemetry_upper",
            "gateway",
            "telemetry_cadence_milliseconds",
            5_001,
        ),
        (
            "gateway_connections",
            "gateway",
            "public_maximum_connections",
            257,
        ),
    ] {
        let mut document = valid.clone();
        document["configuration"][section][field] = Value::from(value);
        cases.push((name, document));
    }
    let mut node_local_workers = valid.clone();
    node_local_workers["configuration"]["node"]["local_api"]["maximum_workers"] = Value::from(65);
    cases.push(("node_local_workers", node_local_workers));
    let mut node_local_timeout = valid.clone();
    node_local_timeout["configuration"]["node"]["local_api"]["read_timeout_milliseconds"] =
        Value::from(60_001);
    cases.push(("node_local_timeout", node_local_timeout));
    let mut gateway_health_workers = valid.clone();
    gateway_health_workers["configuration"]["gateway"]["health"]["maximum_workers"] =
        Value::from(33);
    cases.push(("gateway_health_workers", gateway_health_workers));
    let mut gateway_health_timeout = valid.clone();
    gateway_health_timeout["configuration"]["gateway"]["health"]["read_timeout_milliseconds"] =
        Value::from(10_001);
    cases.push(("gateway_health_timeout", gateway_health_timeout));
    let mut cli_timeout = valid.clone();
    cli_timeout["configuration"]["cli"]["timeout_milliseconds"] = Value::from(0);
    cases.push(("cli_timeout", cli_timeout));
    let mut cli_response = valid.clone();
    cli_response["configuration"]["cli"]["maximum_response_bytes"] = Value::from(1_048_577);
    cases.push(("cli_response", cli_response));
    let mut protection_poll_zero = valid.clone();
    protection_poll_zero["configuration"]["gateway"]["node_protection"]
        ["poll_interval_milliseconds"] = Value::from(0);
    cases.push(("protection_poll_zero", protection_poll_zero));
    let mut protection_poll_equal_cache = valid.clone();
    protection_poll_equal_cache["configuration"]["gateway"]["node_protection"]
        ["poll_interval_milliseconds"] = Value::from(3_000);
    cases.push(("protection_poll_equal_cache", protection_poll_equal_cache));
    let mut watchdog_flush = valid.clone();
    watchdog_flush["configuration"]["watchdog"]["flush_interval_milliseconds"] =
        Value::from(60_001);
    cases.push(("watchdog_flush", watchdog_flush));
    let mut watchdog_protection_root = valid.clone();
    watchdog_protection_root["configuration"]["watchdog"]["protection_root_path"] =
        Value::from("/var/lib/letsinfer/other/protected-placements");
    cases.push(("watchdog_protection_root", watchdog_protection_root));
    let mut watchdog_controllers = valid;
    watchdog_controllers["configuration"]["watchdog"]["maximum_controllers"] = Value::from(17);
    cases.push(("watchdog_controllers", watchdog_controllers));
    cases
}

// Builds one complete version-four installer handoff for a supported platform.
fn input_document(platform: CoreUpdateServicePlatform, temporary: &TempDir) -> Value {
    let root = temporary.path().canonicalize().expect("temporary root");
    let home = root.join("home");
    let letsinfer_home = home.join(".letsinfer");
    let setup = letsinfer_home.join("setup");
    let material = letsinfer_home.join("material");
    let workspace = letsinfer_home.join("trust-workspace");
    let configuration = letsinfer_home.join("configuration");
    for directory in [
        &home,
        &letsinfer_home,
        &setup,
        &material,
        &material.join("state"),
        &workspace,
        &configuration,
    ] {
        create_private_directory(directory);
    }
    let path = |relative: &str| path_text(&material.join(relative));
    let linux = platform == CoreUpdateServicePlatform::Linux;
    let watchdog_material = linux.then(|| {
        json!({
            "authority_private_key_file": path("trust/watchdog-ca.key"),
            "authority_certificate_file": path("trust/watchdog-ca.crt"),
            "server_certificate_file": path("trust/watchdog-server.crt"),
            "server_private_key_file": path("trust/watchdog-server.key"),
            "controller_certificate_file": path("trust/watchdog-controller.crt"),
            "controller_private_key_file": path("trust/watchdog-controller.key"),
            "controller_allowlist_file": path("trust/watchdog-controllers.allow")
        })
    });
    let watchdog_configuration = linux.then(|| {
        json!({
            "data_directory": path("watchdog"),
            "controller_snapshot_path": path_text(&root.join("watchdog-snapshot.json")),
            "site_state_path": path_text(&root.join("site-state.json")),
            "gateway_metrics_path": path("gateway/telemetry.json"),
            "protection_root_path": path("watchdog/protected-placements"),
            "runtime_installation_root": path_text(&letsinfer_home.join("runtime_installations")),
            "runtime_cache_root": path_text(&letsinfer_home.join("cache")),
            "flush_interval_milliseconds": 5000,
            "maximum_controllers": 8,
            "thresholds": {
                "warning_available_bytes": 3000000000_u64,
                "graceful_available_bytes": 2000000000_u64,
                "emergency_available_bytes": 1000000000_u64,
                "swap_stop_bytes": 1000000,
                "psi_some_microseconds": 100000,
                "psi_full_microseconds": 10000,
                "state_failures": 3,
                "containment_grace_milliseconds": 5000
            }
        })
    });
    let benchmark_configuration = linux.then(|| {
        json!({
            "worker_executable": path_text(&root.join("core/bin/li_benchmark_worker")),
            "github_cli_command": "/usr/bin/gh",
            "task_root": path_text(&letsinfer_home.join("benchmark-tasks")),
            "telemetry_root": path_text(&letsinfer_home.join("benchmark-telemetry")),
            "evidence_root": path_text(&letsinfer_home.join("benchmark-evidence")),
            "signing_workspace_root": path_text(&letsinfer_home.join("benchmark-signing")),
            "maximum_runtime_milliseconds": 604800000_u64,
            "stop_grace_milliseconds": 30000,
            "watchdog_timeout_milliseconds": 5000
        })
    });
    let hardware = if linux {
        json!({
            "platform": "linux", "architecture": "x86_64",
            "boot_id_file": "/proc/sys/kernel/random/boot_id",
            "cpu_information_file": "/proc/cpuinfo",
            "memory_information_file": "/proc/meminfo",
            "nvidia_smi_command": "/usr/bin/nvidia-smi", "rdma_command": "/usr/bin/rdma"
        })
    } else {
        json!({
            "platform": "macos", "sysctl_command": "/usr/sbin/sysctl",
            "metal_probe_command": "/opt/letsinfer/bin/li_hardware_macos_probe"
        })
    };
    let pairing = if linux {
        json!({
            "platform": "linux", "discovery_command": "/usr/bin/avahi-publish-service",
            "direct_link_sys_class": "/sys/class", "direct_link_ip_command": "/usr/sbin/ip"
        })
    } else {
        json!({"platform": "macos", "discovery_command": "/usr/bin/dns-sd"})
    };
    let placement_safety = if linux {
        json!({
            "platform": "linux", "maximum_workers": 8,
            "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000,
            "accept_poll_interval_milliseconds": 50,
            "gateway": {"path": "/opt/letsinfer/bin/li_gateway", "executable_sha256": "4".repeat(64), "principal_id": "5".repeat(32)},
            "watchdog": {"path": "/opt/letsinfer/bin/li_watchdog", "executable_sha256": "6".repeat(64), "principal_id": "7".repeat(32)},
            "lease_milliseconds": 3000
        })
    } else {
        json!({"platform": "macos"})
    };
    let model = json!({
        "catalog_source": "https://github.com/letsinferlabs/runtimes/releases/latest/download/catalog.json",
        "catalog_cache_root": path_text(&letsinfer_home.join("catalog_cache")),
        "catalog_hydration_root": path_text(&letsinfer_home.join("catalog_hydration")),
        "http_workspace_root": path_text(&letsinfer_home.join("http_workspace")),
        "installation_root": path_text(&letsinfer_home.join("runtime_installations")),
        "runtime_cache_root": path_text(&letsinfer_home.join("cache")),
        "curl_command": "/usr/bin/curl",
        "docker_command": "/usr/bin/docker",
        "command_working_directory": path_text(&letsinfer_home.join("command_workspace")),
        "placement_material_root": path_text(&letsinfer_home.join("placement_material")),
        "placement_secret_root": path_text(&letsinfer_home.join("placement_secrets")),
        "placement_tls_workspace_root": path_text(&letsinfer_home.join("placement_tls_staging")),
        "first_port": 18000,
        "port_count": 32,
        "endpoint_timeout_milliseconds": 1000,
        "maximum_hardware_age_milliseconds": 60000,
        "group_id": 20,
        "launch_agents_root": (!linux).then(|| path_text(&root.join("LaunchAgents"))),
        "launchctl_command": (!linux).then_some("/bin/launchctl")
    });
    let native = if linux {
        json!({
            "platform": "linux", "openssl_command": "/usr/bin/openssl",
            "machine_identity_file": "/etc/machine-id",
            "watchdog_health": {
                "authority_certificate_file": path("trust/watchdog-ca.crt"),
                "controller_certificate_file": path("trust/watchdog-controller.crt"),
                "controller_private_key_file": path("trust/watchdog-controller.key")
            }
        })
    } else {
        json!({
            "platform": "macos", "openssl_command": "/usr/bin/openssl",
            "machine_identity_command": "/usr/sbin/ioreg",
            "command_timeout_milliseconds": 5000, "command_poll_interval_milliseconds": 10
        })
    };
    json!({
        "schema": {"name": "li_core_setup_input", "version": 5},
        "owner_user_id": unsafe { libc::geteuid() },
        "request": {
            "request_id": "1".repeat(64), "platform": if linux { "linux" } else { "macos" },
            "role": "main", "core_version": "1.0.0", "core_source_identity": "2".repeat(64),
            "display_name": "Home AI", "control_address": "homeai.local",
            "node_private_address": "127.0.0.1:9443", "gateway_private_address": "127.0.0.1:9444",
            "gateway_public_address": "0.0.0.0:8080",
            "watchdog_address": linux.then_some("127.0.0.1:9445")
        },
        "roots": {
            "letsinfer_home": path_text(&letsinfer_home), "home_directory": path_text(&home),
            "setup_state_directory": path_text(&setup), "material_root": path_text(&material),
            "trust_workspace_root": path_text(&workspace),
            "configuration_directory": path_text(&configuration)
        },
        "material": {
            "database_file": path("state/core.sqlite3"),
            "pairing_setup_secret_file": path("trust/pairing.key"),
            "api_key_file": path("trust/api.key"),
            "benchmark_signing": {
                "private_key_file": path("trust/benchmark-signing.key"),
                "public_key_file": path("trust/benchmark-signing.pub")
            },
            "pairing": {
                "site_private_key_file": path("trust/site.key"),
                "site_public_key_file": path("trust/site.pub"),
                "site_ca_certificate_file": path("trust/site-ca.crt"),
                "local_control_certificate_file": path("trust/local-control.crt")
            },
            "node": mutual_tls_material(&path, "node"),
            "gateway": gateway_material(&path),
            "watchdog": watchdog_material
        },
        "configuration": {
            "provider_identity": "3".repeat(64),
            "cli": {
                "entropy_source": "/dev/urandom",
                "launcher_file": "/usr/local/bin/letsinfer",
                "privilege_command": "/usr/bin/sudo",
                "timeout_milliseconds": 5000,
                "maximum_response_bytes": 1048576
            },
            "node": {
                "core_update": {
                    "release_platform": if linux { "linux_x86_64" } else { "macos_arm64" },
                    "letsinfer_home": path_text(&letsinfer_home),
                    "home_directory": path_text(&home),
                    "setup_state_directory": path_text(&setup),
                    "configuration_root": path_text(&configuration),
                    "curl_command": "/usr/bin/curl", "ssh_keygen_command": "/usr/bin/ssh-keygen",
                    "allowed_signers_file": path_text(&letsinfer_home.join("trust/release-allowed-signers")),
                    "supervisor_command": if linux { "/usr/bin/systemctl" } else { "/bin/launchctl" },
                    "readiness_timeout_milliseconds": 30000,
                    "readiness_poll_milliseconds": 100,
                    "stable_readiness_observations": 2
                },
                "model": model, "benchmark": benchmark_configuration,
                "hardware": hardware, "pairing": pairing,
                "placement_safety": placement_safety,
                "trust_workspace": path_text(&workspace.join("pairing_trust_staging")),
                "daemon_cadence_milliseconds": 1000,
                "local_api": local_api(&root.join("node.sock")),
                "remote_maximum_workers": 16, "remote_accept_poll_interval_milliseconds": 100,
                "remote_handshake_timeout_milliseconds": 5000,
                "remote_read_timeout_milliseconds": 5000,
                "remote_write_timeout_milliseconds": 5000
            },
            "gateway": {
                "health": local_api(&root.join("gateway-health.sock")),
                "node_protection": {
                    "socket_path": path_text(&root.join("node-protection.sock")),
                    "read_timeout_milliseconds": 1000,
                    "write_timeout_milliseconds": 1000,
                    "maximum_cache_milliseconds": 3000,
                    "poll_interval_milliseconds": 1000
                },
                "telemetry_file": path("gateway/telemetry.json"),
                "telemetry_cadence_milliseconds": 1000, "maximum_queue_milliseconds": 30000,
                "public_maximum_connections": 64, "private_maximum_connections": 32
            },
            "watchdog": watchdog_configuration
        },
        "native": native
    })
}

// Builds one authority, server, and ordinary client material document.
fn mutual_tls_material(path: &dyn Fn(&str) -> String, name: &str) -> Value {
    json!({
        "authority_private_key_file": path(&format!("trust/{name}-ca.key")),
        "authority_certificate_file": path(&format!("trust/{name}-ca.crt")),
        "server_certificate_file": path(&format!("trust/{name}-server.crt")),
        "server_private_key_file": path(&format!("trust/{name}-server.key")),
        "client_certificate_file": path(&format!("trust/{name}-client.crt")),
        "client_private_key_file": path(&format!("trust/{name}-client.key"))
    })
}

// Builds the Gateway authority, server, and relay-client material document.
fn gateway_material(path: &dyn Fn(&str) -> String) -> Value {
    json!({
        "authority_private_key_file": path("trust/gateway-ca.key"),
        "authority_certificate_file": path("trust/gateway-ca.crt"),
        "server_certificate_file": path("trust/gateway-server.crt"),
        "server_private_key_file": path("trust/gateway-server.key"),
        "relay_client_certificate_file": path("trust/gateway-client.crt"),
        "relay_client_private_key_file": path("trust/gateway-client.key")
    })
}

// Builds one bounded local API document for Node or Gateway health.
fn local_api(socket_path: &Path) -> Value {
    json!({
        "socket_path": path_text(socket_path), "maximum_workers": 8,
        "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000,
        "accept_poll_interval_milliseconds": 10
    })
}

// Produces one canonical closed setup result for the injected application seam.
fn result_document(disposition: &str, platform: CoreUpdateServicePlatform) -> Vec<u8> {
    let services = match platform {
        CoreUpdateServicePlatform::Linux => json!(["li_node", "li_watchdog", "li_gateway"]),
        CoreUpdateServicePlatform::Macos => json!(["li_node", "li_gateway"]),
    };
    let mut bytes = serde_json::to_vec(&json!({
        "schema": {"name": "li_core_setup_result", "version": 1},
        "status": disposition, "node_id": "3".repeat(32), "machine_id": "4".repeat(32),
        "installation_id": "2".repeat(64), "display_name": "Home AI", "role": "main",
        "control_address": "homeai.local", "api_key_file": "/private/api.key",
        "inference_endpoint": "http://homeai.local:8080", "services": services
    }))
    .expect("result JSON");
    bytes.push(b'\n');
    bytes
}

// Encodes one JSON value without adding a second process document.
fn encoded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("input JSON")
}

// Returns the only accepted process argument vector containing the executable identity alone.
fn arguments() -> Vec<OsString> {
    vec![OsString::from("li_core_setup")]
}

// Returns one canonical UTF-8 path string from a test-owned temporary root.
fn path_text(path: &Path) -> String {
    path.to_str().expect("UTF-8 path").to_string()
}

// Creates one private temporary root for real production composition.
fn private_temporary() -> TempDir {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("temporary permissions");
    temporary
}

// Creates one owner-private ordinary directory used by a production provider.
fn create_private_directory(path: &Path) {
    fs::create_dir_all(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("private directory permissions");
}
