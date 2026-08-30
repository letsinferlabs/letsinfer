// SPDX-License-Identifier: AGPL-3.0-only

use std::num::NonZeroU64;

use li_core_interface::{
    BootId, InstallationId, NodeId, PlacementGroupId, PlacementId, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayPlacementProtectionLease, GatewayPlacementProtectionSnapshot, GatewayProtectionAuthority,
};
use li_node_manager::{
    NodeProtectionReadSiteStatusRequest, NodeProtectionRemoteError, NodeProtectionRequest,
    NodeProtectionResolveControllerBindingRequest, NodeProtectionResponse, NodeProtectionTransport,
    NodeProtectionTransportError, NodeProtectionTransportOutcome, NodeProtectionTransportRequest,
    NodeProtectionTransportResponse, NODE_PROTECTION_MAX_DOCUMENT_BYTES,
};
use li_watchdog_manager::{
    WatchdogControllerBinding, WatchdogProtectedEngine, WatchdogProtocolSiteStatus,
};

const BEGIN: &[u8] = include_bytes!("fixtures/protection/li_node_protection_begin_v2.json");
const COMMIT: &[u8] = include_bytes!("fixtures/protection/li_node_protection_commit_v2.json");
const END: &[u8] = include_bytes!("fixtures/protection/li_node_protection_end_v2.json");
const SNAPSHOT: &[u8] = include_bytes!("fixtures/protection/li_node_protection_snapshot_v2.json");

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&identity(character, 64)).expect("digest")
}

// Returns one complete process-bound controller identity for v2 request and response coverage.
fn controller_binding() -> WatchdogControllerBinding {
    WatchdogControllerBinding::new(
        &identity('c', 32),
        &identity('d', 64),
        7,
        WatchdogProtectedEngine::parse(&format!(
            "version=1\ngeneration={}\nphase=armed\ncontainer_name=li_engine\ncontainer_id={}\npid=1234\nstart_ticks=5678\nboot_id=12345678-1234-1234-1234-123456789abc\ncgroup=/sys/fs/cgroup/user.slice/li_engine\n",
            identity('6', 32),
            identity('7', 64),
        ))
        .expect("protected engine"),
    )
    .expect("controller binding")
}

// Returns one complete public site-status projection for v2 response coverage.
fn site_status() -> WatchdogProtocolSiteStatus {
    WatchdogProtocolSiteStatus::new(
        "0.11.0-rc.114".to_string(),
        "model".to_string(),
        "engine".to_string(),
        "runtime".to_string(),
        "1.0.0".to_string(),
        identity('e', 64),
        "persistent".to_string(),
        true,
        9_770,
        64,
        8,
        32_768,
        "running".to_string(),
        "running".to_string(),
        "armed".to_string(),
        true,
        false,
        "li_engine".to_string(),
        identity('f', 64),
    )
    .expect("site status")
}

// Returns one canonical Node identity.
fn node_id() -> NodeId {
    NodeId::parse(&identity('1', 32)).expect("node")
}

// Returns one complete identity-bound snapshot for response roundtrips.
fn protection_snapshot() -> GatewayPlacementProtectionSnapshot {
    let group_id = PlacementGroupId::parse(&identity('8', 32)).expect("group");
    let placement_id = PlacementId::parse(&identity('9', 32)).expect("placement");
    let authority = GatewayProtectionAuthority::new(
        node_id(),
        InstallationId::parse(&identity('2', 64)).expect("installation"),
        digest('3'),
        digest('5'),
        NonZeroU64::new(3).expect("generation"),
    );
    let lease = GatewayPlacementProtectionLease::new(
        node_id(),
        group_id.clone(),
        placement_id.clone(),
        authority.core_installation_id().clone(),
        authority.watchdog_source_identity().clone(),
        authority.watchdog_session_id().clone(),
        authority.watchdog_session_generation(),
        &identity('6', 32),
        TechnicalName::parse("li_engine").expect("container"),
        digest('7'),
        1234,
        5678,
        BootId::parse("12345678-1234-1234-1234-123456789abc").expect("boot"),
        "/sys/fs/cgroup/user.slice/li_engine",
        NonZeroU64::new(8).expect("sample"),
        UnixMilliseconds::new(1_008),
        208,
        UnixMilliseconds::new(2_008),
        true,
        false,
    )
    .expect("lease");
    GatewayPlacementProtectionSnapshot::new(
        group_id,
        vec![(placement_id, node_id())],
        vec![authority],
        vec![lease],
    )
    .expect("snapshot")
}

// Returns one ordinary successful snapshot response.
fn snapshot_response() -> NodeProtectionTransportResponse {
    NodeProtectionTransportResponse::new(
        digest('a'),
        digest('b'),
        NonZeroU64::new(1).expect("sequence"),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::GatewaySnapshot(Some(
            protection_snapshot(),
        ))),
    )
}

// Decodes one JSON value for deterministic mutation.
fn value(document: &[u8]) -> serde_json::Value {
    serde_json::from_slice(document).expect("JSON")
}

// Encodes one mutated JSON value.
fn document(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("document")
}

// Proves ordinary begin, commit, end, and snapshot fixtures roundtrip through typed requests.
#[test]
fn ordinary_request_fixtures_roundtrip() {
    for fixture in [BEGIN, COMMIT, END, SNAPSHOT] {
        let decoded = NodeProtectionTransport::decode_request(fixture).expect("decode");
        let encoded = NodeProtectionTransport::encode_request(&decoded).expect("encode");
        let replay = NodeProtectionTransport::decode_request(&encoded).expect("replay");
        assert_eq!(decoded, replay);
    }
}

// Roundtrips both v2 Watchdog reads and rejects their v1 or structurally altered documents.
#[test]
fn watchdog_protocol_read_codec_is_closed_and_replayable() {
    let requests = [
        NodeProtectionRequest::ResolveControllerBinding(
            NodeProtectionResolveControllerBindingRequest::new(digest('d')),
        ),
        NodeProtectionRequest::ReadSiteStatus(NodeProtectionReadSiteStatusRequest::new(
            controller_binding(),
        )),
    ];
    for (index, request) in requests.into_iter().enumerate() {
        let request = NodeProtectionTransportRequest::new(
            digest(char::from(
                b'a' + u8::try_from(index).expect("bounded index"),
            )),
            digest('b'),
            request,
        );
        let encoded = NodeProtectionTransport::encode_request(&request).expect("encode");
        assert_eq!(
            NodeProtectionTransport::decode_request(&encoded).expect("decode"),
            request
        );
        let mut v1 = value(&encoded);
        v1["schema"]["version"] = serde_json::json!(1);
        assert_eq!(
            NodeProtectionTransport::decode_request(&document(&v1)),
            Err(NodeProtectionTransportError::UnsupportedSchema)
        );
        let mut unknown = value(&encoded);
        unknown["request"]["arguments"]["unknown"] = serde_json::json!(true);
        assert_eq!(
            NodeProtectionTransport::decode_request(&document(&unknown)),
            Err(NodeProtectionTransportError::InvalidDocument)
        );
    }

    let mut invalid_certificate = value(
        &NodeProtectionTransport::encode_request(&NodeProtectionTransportRequest::new(
            digest('a'),
            digest('b'),
            NodeProtectionRequest::ResolveControllerBinding(
                NodeProtectionResolveControllerBindingRequest::new(digest('d')),
            ),
        ))
        .expect("resolve document"),
    );
    invalid_certificate["request"]["arguments"]["certificate_sha256"] =
        serde_json::json!(identity('d', 63));
    assert_eq!(
        NodeProtectionTransport::decode_request(&document(&invalid_certificate)),
        Err(NodeProtectionTransportError::InvalidDocument)
    );
}

// Proves every typed success branch and the closed failure vocabulary roundtrip.
#[test]
fn response_matrix_roundtrips_without_losing_connection_identity() {
    let authority = protection_snapshot().authorities()[0].clone();
    let outcomes = [
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::WatchdogSessionBegan(
            authority,
        )),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::WatchdogCycleCommitted {
            lease_count: 1,
        }),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::WatchdogSessionEnded),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::ControllerBinding(
            controller_binding(),
        )),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::SiteStatus(site_status())),
        snapshot_response().outcome().clone(),
        NodeProtectionTransportOutcome::Failure(NodeProtectionRemoteError::AuthorizationDenied),
        NodeProtectionTransportOutcome::Failure(NodeProtectionRemoteError::InvalidContract),
        NodeProtectionTransportOutcome::Failure(NodeProtectionRemoteError::Conflict),
        NodeProtectionTransportOutcome::Failure(NodeProtectionRemoteError::Corrupt),
        NodeProtectionTransportOutcome::Failure(NodeProtectionRemoteError::ProviderUnavailable),
    ];
    for (index, outcome) in outcomes.into_iter().enumerate() {
        let response = NodeProtectionTransportResponse::new(
            digest('a'),
            digest('b'),
            NonZeroU64::new(index as u64 + 1).expect("sequence"),
            outcome,
        );
        let encoded = NodeProtectionTransport::encode_response(&response).expect("encode");
        assert_eq!(
            NodeProtectionTransport::decode_response(&encoded).expect("decode"),
            response
        );
    }

    let poll = snapshot_response()
        .into_gateway_poll_response()
        .expect("Gateway poll response");
    assert_eq!(poll.connection_id(), &digest('b'));
    assert_eq!(poll.sequence().get(), 1);
    assert_eq!(poll.snapshot().expect("snapshot").leases().len(), 1);
}

// Proves unknown fields, schema changes, invalid identities, and zero bounds fail closed.
#[test]
fn request_envelope_and_begin_mutation_matrix_is_closed() {
    let mut mutations = Vec::new();
    let mut mutation = value(BEGIN);
    mutation["unknown"] = serde_json::json!(true);
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["schema"]["unknown"] = serde_json::json!(true);
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["schema"]["name"] = serde_json::json!("li_node_private_api");
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["schema"]["version"] = serde_json::json!(1);
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["request_id"] = serde_json::json!(identity('a', 63));
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["request"]["arguments"]["unknown"] = serde_json::json!(true);
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["request"]["arguments"]["idempotency_key"] = serde_json::json!("");
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["request"]["arguments"]["minimum_sample_sequence"] = serde_json::json!(0);
    mutations.push(mutation);
    let mut mutation = value(BEGIN);
    mutation["request"]["arguments"]["core_installation_id"] = serde_json::json!(identity('2', 63));
    mutations.push(mutation);

    for (index, mutation) in mutations.into_iter().enumerate() {
        assert!(
            NodeProtectionTransport::decode_request(&document(&mutation)).is_err(),
            "mutation {index} was accepted"
        );
    }
}

// Proves cycle sequence, time, target count, duplicates, phase, and cgroup mutations fail closed.
#[test]
fn completed_cycle_mutation_matrix_is_closed() {
    let mut mutations = Vec::new();
    for field in [
        "sample_sequence",
        "observed_at_unix_milliseconds",
        "observed_at_monotonic_milliseconds",
    ] {
        let mut mutation = value(COMMIT);
        mutation["request"]["arguments"]["cycle"][field] = serde_json::json!(0);
        mutations.push(mutation);
    }
    let mut mutation = value(COMMIT);
    mutation["request"]["arguments"]["watchdog_session_generation"] = serde_json::json!(0);
    mutations.push(mutation);
    let descriptor =
        value(COMMIT)["request"]["arguments"]["cycle"]["protected_descriptors"][0].clone();
    let mut mutation = value(COMMIT);
    mutation["request"]["arguments"]["cycle"]["protected_descriptors"] =
        serde_json::Value::Array(vec![descriptor.clone(), descriptor.clone()]);
    mutations.push(mutation);
    let descriptor_text = descriptor.as_str().expect("descriptor");
    for changed in [
        descriptor_text.replace("phase=armed", "phase=starting"),
        descriptor_text.replace(
            "cgroup=/sys/fs/cgroup/user.slice/li_engine",
            "cgroup=/sys/fs/cgroup//user.slice/li_engine",
        ),
        descriptor_text.replace(
            "cgroup=/sys/fs/cgroup/user.slice/li_engine",
            "cgroup=/sys/fs/cgroup/user.slice/./li_engine",
        ),
        descriptor_text.replace(
            "cgroup=/sys/fs/cgroup/user.slice/li_engine",
            "cgroup=/sys/fs/cgroup/user.slice/li_engine/",
        ),
    ] {
        let mut mutation = value(COMMIT);
        mutation["request"]["arguments"]["cycle"]["protected_descriptors"][0] =
            serde_json::json!(changed);
        mutations.push(mutation);
    }
    let mut mutation = value(COMMIT);
    mutation["request"]["arguments"]["cycle"]["protected_descriptors"] =
        serde_json::Value::Array(vec![descriptor; 65]);
    mutations.push(mutation);

    for (index, mutation) in mutations.into_iter().enumerate() {
        assert!(
            NodeProtectionTransport::decode_request(&document(&mutation)).is_err(),
            "cycle mutation {index} was accepted"
        );
    }
}

// Proves response connection, sequence, nested lease, and failure-code mutations fail closed.
#[test]
fn response_mutation_matrix_is_closed() {
    let encoded = NodeProtectionTransport::encode_response(&snapshot_response()).expect("response");
    let mut mutations = Vec::new();
    let mut mutation = value(&encoded);
    mutation["connection_id"] = serde_json::json!(identity('b', 63));
    mutations.push(mutation);
    let mut mutation = value(&encoded);
    mutation["sequence"] = serde_json::json!(0);
    mutations.push(mutation);
    let mut mutation = value(&encoded);
    mutation["outcome"]["body"]["value"]["snapshot"]["leases"][0]["cgroup"] =
        serde_json::json!("/sys/fs/cgroup//user.slice/li_engine");
    mutations.push(mutation);
    let mut mutation = value(&encoded);
    mutation["outcome"]["body"]["value"]["snapshot"]["leases"][0]["unknown"] =
        serde_json::json!(true);
    mutations.push(mutation);
    let binding = NodeProtectionTransportResponse::new(
        digest('a'),
        digest('b'),
        NonZeroU64::new(1).expect("sequence"),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::ControllerBinding(
            controller_binding(),
        )),
    );
    let mut mutation =
        value(&NodeProtectionTransport::encode_response(&binding).expect("binding response"));
    mutation["outcome"]["body"]["value"]["session_generation"] = serde_json::json!(0);
    mutations.push(mutation);
    let status = NodeProtectionTransportResponse::new(
        digest('a'),
        digest('b'),
        NonZeroU64::new(1).expect("sequence"),
        NodeProtectionTransportOutcome::Success(NodeProtectionResponse::SiteStatus(site_status())),
    );
    let mut mutation =
        value(&NodeProtectionTransport::encode_response(&status).expect("status response"));
    mutation["outcome"]["body"]["value"]["maximum_connections"] = serde_json::json!(0);
    mutations.push(mutation);
    let failure = NodeProtectionTransportResponse::new(
        digest('a'),
        digest('b'),
        NonZeroU64::new(1).expect("sequence"),
        NodeProtectionTransportOutcome::Failure(NodeProtectionRemoteError::Conflict),
    );
    let mut mutation =
        value(&NodeProtectionTransport::encode_response(&failure).expect("failure response"));
    mutation["outcome"]["body"]["code"] = serde_json::json!("unknown");
    mutations.push(mutation);

    for mutation in mutations {
        assert!(NodeProtectionTransport::decode_response(&document(&mutation)).is_err());
    }
}

// Proves the transport enforces its byte bound before JSON parsing.
#[test]
fn oversized_document_fails_before_decode() {
    let document = vec![b' '; NODE_PROTECTION_MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        NodeProtectionTransport::decode_request(&document),
        Err(NodeProtectionTransportError::DocumentTooLarge)
    );
}

// Proves the checked-in wire schema retains current identity and closed top-level definitions.
#[test]
fn checked_in_transport_schema_is_current_and_closed() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/node/li_node_protection_api_v2.schema.json"
    ))
    .expect("schema");

    assert_eq!(
        schema["$id"],
        "https://letsinfer.ai/schemas/node/li_node_protection_api_v2.schema.json"
    );
    assert_eq!(
        schema["$defs"]["schema_identity"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["schema_identity"]["properties"]["version"]["const"],
        2
    );
    assert_eq!(
        schema["$defs"]["request_envelope"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["response_envelope"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["controller_binding"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["site_status"]["additionalProperties"],
        false
    );
}
