// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayConfigurationMode, GatewayNativeFile,
    GatewayNativeFileIo, GatewayNativeIoError, LI_GATEWAY_CONFIGURATION_SCHEMA_NAME,
    LI_GATEWAY_CONFIGURATION_SCHEMA_VERSION,
};
use serde_json::{json, Value};

const CONFIGURATION_PATH: &str = "/private/li_gateway.json";
const OWNER_USER_ID: u32 = 501;

// Returns one exact schema-5 configuration document for the selected process mode.
fn document(mode: &str) -> Value {
    let mut document = json!({
        "schema": {
            "name": "li_gateway_configuration",
            "version": 5
        },
        "node_id": "11111111111111111111111111111111",
        "core_release": "1.2.3",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "mode": mode,
        "health": {
            "socket_path": "/private/gateway_health.sock",
            "maximum_workers": 8,
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "accept_poll_interval_milliseconds": 10
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
            "address": "127.0.0.1:0",
            "maximum_connections": 32,
            "tls": {
                "server_certificate_file": "/private/gateway.crt",
                "server_private_key_file": "/private/gateway.key",
                "client_ca_file": "/private/main-ca.crt",
                "client_certificate_file": "/private/main.crt"
            }
        }
    });
    if mode == "main" {
        document.as_object_mut().unwrap().insert(
            "public_listener".to_string(),
            json!({
                "address": "127.0.0.1:1",
                "maximum_connections": 64
            }),
        );
    }
    document
}

// Supplies one configurable no-follow file observation and records its requested bound.
struct MockFileIo {
    file: Mutex<Option<GatewayNativeFile>>,
    maximum_bytes: Mutex<Vec<usize>>,
}

impl MockFileIo {
    // Creates one provider containing an exact file observation.
    fn new(file: GatewayNativeFile) -> Self {
        Self {
            file: Mutex::new(Some(file)),
            maximum_bytes: Mutex::new(Vec::new()),
        }
    }
}

impl GatewayNativeFileIo for MockFileIo {
    // Returns the configured observation only for the exact configuration path.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        self.maximum_bytes.lock().unwrap().push(maximum_bytes);
        if path != Path::new(CONFIGURATION_PATH) {
            return Err(GatewayNativeIoError::terminal_before_head("missing"));
        }
        let file = self
            .file
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| GatewayNativeIoError::terminal_before_head("missing"))?;
        if file.bytes().len() > maximum_bytes {
            return Err(GatewayNativeIoError::terminal_before_head("oversized"));
        }
        Ok(file)
    }
}

// Creates one safe owner-only configuration observation from exact JSON bytes.
fn safe_file(bytes: Vec<u8>) -> GatewayNativeFile {
    GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, bytes).unwrap()
}

// Loads one document through the production metadata and JSON boundary.
fn load(
    value: Value,
) -> Result<GatewayConfiguration, li_gateway_manager::GatewayConfigurationError> {
    let io = MockFileIo::new(safe_file(serde_json::to_vec(&value).unwrap()));
    let file =
        GatewayConfigurationFile::new(OWNER_USER_ID, PathBuf::from(CONFIGURATION_PATH)).unwrap();
    GatewayConfiguration::load(&file, &io)
}

// Proves main and child documents produce only their exact required listener sets.
#[test]
fn configuration_loads_exact_main_and_child_shapes() {
    let main = load(document("main")).unwrap();
    assert_eq!(main.mode(), GatewayConfigurationMode::Main);
    assert_eq!(main.node_id().as_str(), "1".repeat(32));
    assert_eq!(main.core_version().as_str(), "1.2.3");
    assert_eq!(main.core_source_identity().as_str(), "c".repeat(64));
    assert_eq!(
        main.health().socket_path(),
        Path::new("/private/gateway_health.sock")
    );
    assert_eq!(main.health().owner_user_id(), OWNER_USER_ID);
    assert_eq!(main.health().maximum_workers(), 8);
    assert_eq!(
        main.node_protection().expect("protection").socket_path(),
        Path::new("/private/node_protection.sock")
    );
    assert_eq!(
        main.node_protection().expect("protection").poll_interval(),
        std::time::Duration::from_millis(500)
    );
    assert_eq!(
        main.public_listener().unwrap().address().to_string(),
        "127.0.0.1:1"
    );
    assert_eq!(main.public_listener().unwrap().maximum_connections(), 64);
    assert_eq!(
        main.private_listener().listener().address().to_string(),
        "127.0.0.1:0"
    );
    assert_eq!(main.private_listener().listener().maximum_connections(), 32);
    assert_eq!(main.node_socket_path(), Path::new("/private/node.sock"));
    assert_eq!(
        main.telemetry_file(),
        Path::new("/private/gateway_telemetry_v2")
    );
    assert_eq!(main.telemetry_cadence(), std::time::Duration::from_secs(1));
    assert_eq!(main.maximum_queue_milliseconds(), 30_000);

    let child = load(document("child")).unwrap();
    assert_eq!(child.mode(), GatewayConfigurationMode::Child);
    assert!(child.public_listener().is_none());
    assert_eq!(
        child.private_listener().listener().address().to_string(),
        "127.0.0.1:0"
    );
}

// Proves no-follow metadata, ownership, mode, links, size, and absolute path fail closed.
#[test]
fn configuration_file_safety_matrix_is_closed_and_bounded() {
    assert!(GatewayConfigurationFile::new(OWNER_USER_ID, PathBuf::from("relative.json")).is_err());
    let bytes = serde_json::to_vec(&document("child")).unwrap();
    let unsafe_files = [
        GatewayNativeFile::new(502, 0o600, 1, bytes.clone()).unwrap(),
        GatewayNativeFile::new(OWNER_USER_ID, 0o640, 1, bytes.clone()).unwrap(),
        GatewayNativeFile::new(OWNER_USER_ID, 0o600, 2, bytes.clone()).unwrap(),
        GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, Vec::new()).unwrap(),
    ];
    let reference =
        GatewayConfigurationFile::new(OWNER_USER_ID, PathBuf::from(CONFIGURATION_PATH)).unwrap();
    for unsafe_file in unsafe_files {
        let io = MockFileIo::new(unsafe_file);
        assert_eq!(
            GatewayConfiguration::load(&reference, &io)
                .unwrap_err()
                .reason(),
            "Gateway configuration file metadata is unsafe"
        );
        assert_eq!(io.maximum_bytes.lock().unwrap().as_slice(), [64 * 1024]);
    }
    let oversized = MockFileIo::new(
        GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, vec![b' '; 64 * 1024 + 1]).unwrap(),
    );
    assert_eq!(
        GatewayConfiguration::load(&reference, &oversized)
            .unwrap_err()
            .reason(),
        "Gateway configuration file is unavailable"
    );
}

// Proves unknown, duplicate, malformed, and unsupported schema fields cannot be reinterpreted.
#[test]
fn configuration_json_identity_and_field_set_are_strict() {
    let mut unknown = document("child");
    unknown
        .as_object_mut()
        .unwrap()
        .insert("future".to_string(), Value::Bool(true));
    assert_eq!(
        load(unknown).unwrap_err().reason(),
        "Gateway configuration document is invalid"
    );

    let duplicate = br#"{
      "schema":{"name":"li_gateway_configuration","version":5},
      "node_id":"11111111111111111111111111111111",
      "core_release":"1.2.3",
      "core_source_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "mode":"child",
      "mode":"main",
      "health":{
        "socket_path":"/private/gateway_health.sock",
        "maximum_workers":8,
        "read_timeout_milliseconds":1000,
        "write_timeout_milliseconds":1000,
        "accept_poll_interval_milliseconds":10
      },
      "node_protection":{
        "socket_path":"/private/node_protection.sock",
        "read_timeout_milliseconds":1000,
        "write_timeout_milliseconds":1000,
        "maximum_cache_milliseconds":2000,
        "poll_interval_milliseconds":500
      },
      "runtime":{
        "node_socket_path":"/private/node.sock",
        "telemetry_file":"/private/gateway_telemetry_v2",
        "telemetry_cadence_milliseconds":1000,
        "maximum_queue_milliseconds":30000
      },
      "private_listener":{
        "address":"127.0.0.1:0",
        "maximum_connections":1,
        "tls":{
          "server_certificate_file":"/a",
          "server_private_key_file":"/b",
          "client_ca_file":"/c",
          "client_certificate_file":"/d"
        }
      }
    }"#
    .to_vec();
    let io = MockFileIo::new(safe_file(duplicate));
    let reference =
        GatewayConfigurationFile::new(OWNER_USER_ID, PathBuf::from(CONFIGURATION_PATH)).unwrap();
    assert_eq!(
        GatewayConfiguration::load(&reference, &io)
            .unwrap_err()
            .reason(),
        "Gateway configuration document is invalid"
    );

    let mut schema = document("child");
    schema["schema"]["version"] = Value::from(1);
    assert_eq!(
        load(schema).unwrap_err().reason(),
        "Gateway configuration schema is unsupported"
    );
}

// Proves mode shape, IP literals, worker bounds, bind uniqueness, and TLS roles are semantic gates.
#[test]
fn configuration_semantic_mutation_matrix_is_rejected() {
    let mut main_without_public = document("main");
    main_without_public
        .as_object_mut()
        .unwrap()
        .remove("public_listener");
    let mut child_with_public = document("child");
    child_with_public.as_object_mut().unwrap().insert(
        "public_listener".to_string(),
        json!({"address":"127.0.0.1:1","maximum_connections":1}),
    );
    let mut dns_address = document("child");
    dns_address["private_listener"]["address"] = Value::from("localhost:9000");
    let mut unbounded = document("child");
    unbounded["private_listener"]["maximum_connections"] = Value::from(257);
    let mut duplicate_address = document("main");
    duplicate_address["public_listener"]["address"] = Value::from("127.0.0.1:0");
    let mut relative_tls = document("child");
    relative_tls["private_listener"]["tls"]["client_ca_file"] = Value::from("ca.crt");
    let mut duplicate_tls = document("child");
    duplicate_tls["private_listener"]["tls"]["client_ca_file"] =
        Value::from("/private/gateway.crt");
    let mut relative_node_socket = document("child");
    relative_node_socket["runtime"]["node_socket_path"] = Value::from("node.sock");
    let mut ambiguous_node_socket = document("child");
    ambiguous_node_socket["runtime"]["node_socket_path"] =
        Value::from("/private/gateway_health.sock");
    let mut short_cadence = document("child");
    short_cadence["runtime"]["telemetry_cadence_milliseconds"] = Value::from(99);
    let mut unbounded_queue = document("child");
    unbounded_queue["runtime"]["maximum_queue_milliseconds"] = Value::from(300_001);
    let mut invalid_node = document("child");
    invalid_node["node_id"] = Value::from("not-a-node");
    let mut invalid_release = document("child");
    invalid_release["core_release"] = Value::from("v1.2.3");
    let mut invalid_source = document("child");
    invalid_source["core_source_identity"] = Value::from("c".repeat(63));
    let mut relative_health = document("child");
    relative_health["health"]["socket_path"] = Value::from("gateway.sock");
    let mut unbounded_health_workers = document("child");
    unbounded_health_workers["health"]["maximum_workers"] = Value::from(33);
    let mut zero_health_timeout = document("child");
    zero_health_timeout["health"]["read_timeout_milliseconds"] = Value::from(0);
    let mut zero_protection_poll = document("child");
    zero_protection_poll["node_protection"]["poll_interval_milliseconds"] = Value::from(0);
    let mut equal_protection_poll = document("child");
    equal_protection_poll["node_protection"]["poll_interval_milliseconds"] = Value::from(2_000);
    let mut greater_protection_poll = document("child");
    greater_protection_poll["node_protection"]["poll_interval_milliseconds"] = Value::from(2_001);
    let mut maximum_protection_poll = document("child");
    maximum_protection_poll["node_protection"]["maximum_cache_milliseconds"] = Value::from(60_000);
    maximum_protection_poll["node_protection"]["poll_interval_milliseconds"] = Value::from(30_000);

    for mutation in [
        main_without_public,
        child_with_public,
        dns_address,
        unbounded,
        duplicate_address,
        relative_tls,
        duplicate_tls,
        relative_node_socket,
        ambiguous_node_socket,
        short_cadence,
        unbounded_queue,
        invalid_node,
        invalid_release,
        invalid_source,
        relative_health,
        unbounded_health_workers,
        zero_health_timeout,
        zero_protection_poll,
        equal_protection_poll,
        greater_protection_poll,
        maximum_protection_poll,
    ] {
        assert!(load(mutation).is_err());
    }
}

// Proves the distributed JSON Schema carries the exact runtime identity and closed role shape.
#[test]
fn top_level_json_schema_matches_runtime_identity() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/gateway/li_gateway_configuration_v5.schema.json"
    ))
    .unwrap();

    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        LI_GATEWAY_CONFIGURATION_SCHEMA_NAME
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        LI_GATEWAY_CONFIGURATION_SCHEMA_VERSION
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["$defs"]["listener"]["properties"]["maximum_connections"]["maximum"],
        256
    );
    assert_eq!(schema["allOf"].as_array().unwrap().len(), 2);
    assert_eq!(
        schema["properties"]["health"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["health"]["properties"]["maximum_workers"]["maximum"],
        32
    );
}
