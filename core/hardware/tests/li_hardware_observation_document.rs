// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    Accelerator, AcceleratorDriver, AcceleratorMemory, AcceleratorTelemetry, AcceleratorVendor,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, DeviceId, DisplayName,
    HardwareObservation, HardwareObservationId, InterconnectObservation,
    InterconnectObservationKind, MemoryTopology, NetworkInterfaceName, NodeId, OperatingSystem,
    PlatformIdentity, ProcessorObservation, TechnicalName, UnixMilliseconds,
};
use li_hardware_manager::{
    decode_hardware_observation, encode_hardware_observation, HardwareError,
};
use serde_json::Value;

const SCHEMA: &str =
    include_str!("../../../schemas/hardware/li_hardware_observation_v1.schema.json");

// Returns one rich Linux observation with immutable identity and mutable topology facts.
fn observation() -> HardwareObservation {
    let gpu_zero = DeviceId::parse("GPU-00000000-0000-0000-0000-000000000001").expect("GPU zero");
    let gpu_one = DeviceId::parse("GPU-00000000-0000-0000-0000-000000000002").expect("GPU one");
    let nvidia = Accelerator::new(
        gpu_zero.clone(),
        AcceleratorVendor::Nvidia,
        DisplayName::parse("NVIDIA GB10").expect("name"),
        AcceleratorMemory::new(
            MemoryTopology::Discrete,
            Some(ByteCount::new(32 * 1024 * 1024 * 1024).expect("framebuffer")),
            Some(TechnicalName::parse("vram").expect("addressing")),
        )
        .expect("memory"),
        ComputeCapability::Cuda {
            architecture: TechnicalName::parse("sm_121").expect("architecture"),
            maximum_version: Some(TechnicalName::parse("cuda_13.0").expect("CUDA")),
        },
    )
    .with_driver(AcceleratorDriver::new(
        TechnicalName::parse("nvidia").expect("driver source"),
        TechnicalName::parse("580.95.05").expect("driver version"),
    ))
    .with_telemetry(
        AcceleratorTelemetry::new(
            Some(65_000),
            Some(2_500),
            Some(2_000),
            Some(500),
            Some(350_500),
            Some(1024 * 1024 * 1024),
        )
        .expect("telemetry"),
    );
    let auxiliary = Accelerator::new(
        gpu_one.clone(),
        AcceleratorVendor::Other(TechnicalName::parse("fixture").expect("vendor")),
        DisplayName::parse("Fixture Accelerator").expect("name"),
        AcceleratorMemory::new(MemoryTopology::Unknown, None, None).expect("memory"),
        ComputeCapability::Other {
            api: TechnicalName::parse("fixture_api").expect("API"),
            capability: None,
        },
    );
    HardwareObservation::new(
        HardwareObservationId::parse(&"a".repeat(32)).expect("observation"),
        NodeId::parse(&"b".repeat(32)).expect("node"),
        BootId::parse("boot-fixture").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("NVIDIA GB10").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 * 1024 * 1024 * 1024).expect("host memory"),
        vec![nvidia, auxiliary],
        vec![
            InterconnectObservation::new(
                InterconnectObservationKind::Nvlink,
                None,
                vec![gpu_zero, gpu_one],
                true,
                Some(900_000),
                None,
            )
            .expect("NVLink"),
            InterconnectObservation::new(
                InterconnectObservationKind::Rdma,
                Some(NetworkInterfaceName::parse("enp1s0").expect("interface")),
                Vec::new(),
                false,
                Some(200_000),
                Some(9_000),
            )
            .expect("RDMA"),
        ],
        UnixMilliseconds::new(1_787_857_503_000),
    )
    .expect("hardware observation")
}

// Decodes one JSON value through the public strict HardwareManager boundary.
fn decode_value(value: &Value) -> Result<HardwareObservation, HardwareError> {
    decode_hardware_observation(&serde_json::to_vec(value).expect("JSON value"))
}

// Requires every explicitly typed JSON object in the checked-in schema to remain closed.
fn assert_closed_schema_objects(value: &Value) {
    if value.get("type") == Some(&Value::String("object".to_string())) {
        assert_eq!(
            value.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "schema object is open: {value}"
        );
    }
    match value {
        Value::Array(values) => values.iter().for_each(assert_closed_schema_objects),
        Value::Object(values) => values.values().for_each(assert_closed_schema_objects),
        _ => {}
    }
}

// Preserves driver, CUDA, telemetry, topology, boot, and observation identities exactly.
#[test]
fn hardware_observation_document_round_trips_exactly() {
    let observation = observation();
    let encoded = encode_hardware_observation(&observation).expect("encoded observation");
    assert_eq!(
        decode_hardware_observation(&encoded).expect("decoded observation"),
        observation
    );
    let value: Value = serde_json::from_slice(&encoded).expect("JSON");
    assert_eq!(value["schema"]["name"], "li_hardware_observation");
    assert_eq!(value["schema"]["version"], 1);
    assert_eq!(value["accelerators"][0]["driver"]["version"], "580.95.05");
    assert_eq!(
        value["accelerators"][0]["compute"]["maximum_version"],
        "cuda_13.0"
    );
    assert_eq!(value["interconnects"][1]["is_available"], false);
    assert_eq!(value["boot_id"], "boot-fixture");
}

// Binds the checked-in strict schema identity and collection bounds to the producer.
#[test]
fn hardware_observation_schema_matches_the_producer_contract() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("hardware schema");
    assert_eq!(
        schema["$id"],
        "https://letsinfer.ai/schemas/hardware/li_hardware_observation_v1.schema.json"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        "li_hardware_observation"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        1
    );
    assert_eq!(schema["properties"]["accelerators"]["maxItems"], 64);
    assert_eq!(schema["properties"]["interconnects"]["maxItems"], 256);
    let required = schema["$defs"]["accelerator"]["required"]
        .as_array()
        .expect("accelerator required fields");
    assert!(required.contains(&Value::String("driver".to_string())));
    assert!(required.contains(&Value::String("telemetry".to_string())));
    assert_closed_schema_objects(&schema);
}

// Rejects duplicate and unknown fields at root and nested object boundaries.
#[test]
fn hardware_observation_document_rejects_duplicate_and_unknown_fields() {
    let encoded = String::from_utf8(encode_hardware_observation(&observation()).expect("encoded"))
        .expect("UTF-8");
    let duplicate_root = encoded.replacen(
        "\"observation_id\":",
        "\"observation_id\":\"cccccccccccccccccccccccccccccccc\",\"observation_id\":",
        1,
    );
    let duplicate_nested = encoded.replacen(
        "\"source\":",
        "\"source\":\"secret_duplicate\",\"source\":",
        1,
    );
    for bytes in [duplicate_root.as_bytes(), duplicate_nested.as_bytes()] {
        assert!(matches!(
            decode_hardware_observation(bytes),
            Err(HardwareError::InvalidObservation { .. })
        ));
    }
    let mut value: Value = serde_json::from_str(&encoded).expect("JSON");
    value["unknown"] = Value::Bool(true);
    assert!(decode_value(&value).is_err());
    let mut value: Value = serde_json::from_str(&encoded).expect("JSON");
    value["accelerators"][0]["driver"]["secret"] = Value::Bool(true);
    assert!(decode_value(&value).is_err());
    let mut value: Value = serde_json::from_str(&encoded).expect("JSON");
    value["interconnects"][0]["secret"] = Value::Bool(true);
    assert!(decode_value(&value).is_err());
}

// Rejects missing required-nullable fields and unsupported structural variants.
#[test]
fn hardware_observation_document_rejects_structural_mutations() {
    let encoded = encode_hardware_observation(&observation()).expect("encoded");
    let base: Value = serde_json::from_slice(&encoded).expect("JSON");
    for (section, field) in [
        ("accelerators", "driver"),
        ("accelerators", "telemetry"),
        ("interconnects", "interface"),
        ("interconnects", "speed_mbps"),
    ] {
        let mut value = base.clone();
        value[section][0]
            .as_object_mut()
            .expect("object")
            .remove(field);
        assert!(decode_value(&value).is_err(), "missing {section}.{field}");
    }
    for (pointer, replacement) in [
        ("/schema/name", Value::String("li_future".to_string())),
        ("/schema/version", Value::from(2)),
        (
            "/platform/architecture",
            Value::String("future".to_string()),
        ),
        (
            "/accelerators/0/compute/api",
            Value::String("future".to_string()),
        ),
        ("/interconnects/0/kind", Value::String("future".to_string())),
    ] {
        let mut value = base.clone();
        *value.pointer_mut(pointer).expect("mutation pointer") = replacement;
        assert!(decode_value(&value).is_err(), "unsupported {pointer}");
    }
}

// Rejects values that parse structurally but violate shared hardware invariants.
#[test]
fn hardware_observation_document_rejects_semantic_mutations() {
    let encoded = encode_hardware_observation(&observation()).expect("encoded");
    let base: Value = serde_json::from_slice(&encoded).expect("JSON");
    for (pointer, replacement) in [
        ("/memory_bytes", Value::from(0)),
        ("/processor/logical_cpu_count", Value::from(0)),
        (
            "/accelerators/0/telemetry/utilization_per_mille",
            Value::from(1_001),
        ),
        ("/interconnects/0/speed_mbps", Value::from(0)),
    ] {
        let mut value = base.clone();
        *value.pointer_mut(pointer).expect("mutation pointer") = replacement;
        assert!(decode_value(&value).is_err(), "invalid {pointer}");
    }
    let mut duplicate_device = base.clone();
    duplicate_device["accelerators"][1]["device_id"] =
        duplicate_device["accelerators"][0]["device_id"].clone();
    assert!(decode_value(&duplicate_device).is_err());
    let mut unknown_link_device = base;
    unknown_link_device["interconnects"][0]["device_ids"][0] =
        Value::String("GPU-not-observed".to_string());
    assert!(decode_value(&unknown_link_device).is_err());
}

// Rejects empty and oversized documents with stable redacted diagnostics.
#[test]
fn hardware_observation_document_rejects_unbounded_or_sensitive_input() {
    let secret = "secret_hardware_payload";
    for bytes in [
        Vec::new(),
        vec![b'x'; 4 * 1024 * 1024 + 1],
        secret.as_bytes().to_vec(),
    ] {
        let error = decode_hardware_observation(&bytes).expect_err("invalid document");
        assert!(matches!(error, HardwareError::InvalidObservation { .. }));
        assert!(!error.to_string().contains(secret));
    }
}
