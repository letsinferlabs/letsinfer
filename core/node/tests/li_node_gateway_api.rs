// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use li_authentication_manager::{ApiKeyLimits, ApiKeyModelScope};
use li_core_interface::{
    ApiKeyId, BootId, DeviceId, EndpointAddress, EndpointOwnership, EndpointScheme,
    EntityTimestamps, HardwareObservationId, LogicalModelName, NodeAddress, NodeId, NodeRole,
    Placement, PlacementAssignment, PlacementGroupId, PlacementId, PlacementResources,
    PlacementState, PortRange, RuntimeInstallationId, Sha256Digest, TaskId, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayNativeTarget, GatewayPrincipal, GatewayRoute, GatewayRouteTarget, GatewayUsageRecord,
};
use li_node_manager::{
    NodeGatewayApi, NodeGatewayApiError, NodeGatewayBearer, NodeGatewayCapabilityPort,
    NodeGatewayMacOsPlacement, NodeGatewayMacOsSafetyInput, NodeGatewayRequest,
    NodeGatewayResponse, NodeGatewayUsageDisposition, NodePrivateApiError, NodePrivateRequest,
    NodePrivateResponse, NodePrivateTransport, NodePrivateTransportOutcome,
    NodePrivateTransportRequest, NodePrivateTransportResponse, NODE_GATEWAY_MAXIMUM_ROUTES,
};

// Records exact capability order while returning complete deterministic values.
struct GatewayCapabilities {
    calls: Mutex<Vec<&'static str>>,
    route_count: usize,
}

impl GatewayCapabilities {
    // Creates one ordinary provider with a single route.
    fn ordinary() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            route_count: 1,
        }
    }

    // Records one exact capability call.
    fn record(&self, call: &'static str) {
        self.calls.lock().expect("calls").push(call);
    }
}

impl NodeGatewayCapabilityPort for GatewayCapabilities {
    // Authenticates one exact ordinary bearer or returns a redacted denial.
    fn authorize_inference(
        &self,
        bearer: &str,
        _model: &LogicalModelName,
    ) -> Result<GatewayPrincipal, NodeGatewayApiError> {
        self.record("authorize_inference");
        if bearer == "denied" {
            return Err(NodeGatewayApiError::AuthorizationDenied);
        }
        Ok(principal())
    }

    // Returns one selected model scope after recording the request.
    fn authorize_model_list(&self, _bearer: &str) -> Result<ApiKeyModelScope, NodeGatewayApiError> {
        self.record("authorize_model_list");
        ApiKeyModelScope::selected(vec![model()]).map_err(|_| NodeGatewayApiError::InvalidContract)
    }

    // Returns the configured number of identical bounded routes.
    fn routes(&self, _model: &LogicalModelName) -> Result<Vec<GatewayRoute>, NodeGatewayApiError> {
        self.record("routes");
        Ok(vec![route(); self.route_count])
    }

    // Returns one exact local Engine target.
    fn native_target(
        &self,
        _route: &GatewayRoute,
    ) -> Result<GatewayNativeTarget, NodeGatewayApiError> {
        self.record("native_target");
        Ok(native_target())
    }

    // Authenticates one inbound relay as the exact main identity.
    fn authorize_inbound_relay(&self, _bearer: &str) -> Result<NodeId, NodeGatewayApiError> {
        self.record("authorize_inbound_relay");
        Ok(node_id('2'))
    }

    // Returns one completed rolling-window usage record.
    fn recent_usage(
        &self,
        _key_id: &ApiKeyId,
        _since: UnixMilliseconds,
    ) -> Result<Vec<GatewayUsageRecord>, NodeGatewayApiError> {
        self.record("recent_usage");
        Ok(vec![usage()])
    }

    // Confirms an exact idempotent replay for deterministic mapping coverage.
    fn record_usage(
        &self,
        _usage: &GatewayUsageRecord,
    ) -> Result<NodeGatewayUsageDisposition, NodeGatewayApiError> {
        self.record("record_usage");
        Ok(NodeGatewayUsageDisposition::Replayed)
    }

    // Returns one exact placement and launch-plan binding.
    fn macos_safety_input(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<NodeGatewayMacOsSafetyInput, NodeGatewayApiError> {
        self.record("macos_safety_input");
        macos_input(placement_group_id.clone())
    }
}

// Returns one repeated lowercase hexadecimal identity.
fn identity(character: char, length: usize) -> String {
    character.to_string().repeat(length)
}

// Returns one canonical Node identity.
fn node_id(character: char) -> NodeId {
    NodeId::parse(&identity(character, 32)).expect("node")
}

// Returns one canonical logical model.
fn model() -> LogicalModelName {
    LogicalModelName::parse("qwen3_8").expect("model")
}

// Returns one complete current local Engine route.
fn route() -> GatewayRoute {
    GatewayRoute::new(
        PlacementGroupId::parse(&identity('3', 32)).expect("group"),
        node_id('1'),
        model(),
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.1").expect("address"),
                18_000,
            )
            .expect("endpoint"),
        },
        NonZeroU32::new(4).expect("requests"),
        NonZeroU64::new(131_072).expect("context"),
        true,
        false,
        Some(55_000),
        vec![Sha256Digest::parse(&identity('4', 64)).expect("prefix")],
    )
    .expect("route")
}

// Returns one complete exact local Engine target.
fn native_target() -> GatewayNativeTarget {
    let GatewayRouteTarget::LocalEngine { endpoint } = route().target().clone() else {
        panic!("local route");
    };
    GatewayNativeTarget::local_engine(
        &endpoint,
        501,
        PathBuf::from("/private/letsinfer/bearer"),
        PathBuf::from("/private/letsinfer/ca.pem"),
        None,
    )
    .expect("target")
}

// Returns one authenticated public principal without bearer material.
fn principal() -> GatewayPrincipal {
    GatewayPrincipal::new(
        ApiKeyId::parse(&identity('5', 32)).expect("key"),
        ApiKeyLimits::new(None, None, NonZeroU32::new(2), NonZeroU64::new(131_072)),
    )
}

// Returns one coherent completed usage record.
fn usage() -> GatewayUsageRecord {
    GatewayUsageRecord::new(
        Sha256Digest::parse(&identity('6', 64)).expect("request"),
        principal().key_id().clone(),
        UnixMilliseconds::new(1_000),
        UnixMilliseconds::new(2_000),
        512,
    )
    .expect("usage")
}

// Returns one complete running placement for native macOS observation.
fn placement(placement_group_id: PlacementGroupId) -> Placement {
    Placement::new(
        PlacementId::parse(&identity('7', 32)).expect("placement"),
        placement_group_id,
        PlacementAssignment::new(
            node_id('1'),
            RuntimeInstallationId::parse(&identity('8', 32)).expect("runtime"),
            HardwareObservationId::parse(&identity('9', 32)).expect("observation"),
            BootId::parse("boot-fixture").expect("boot"),
            UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse("127.0.0.1").expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 1).expect("ports"),
                vec![DeviceId::parse("apple-gpu-0").expect("device")],
                None,
            )
            .expect("resources"),
            EndpointOwnership::Owner,
        ),
        PlacementState::Running,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns one exact bounded macOS safety input.
fn macos_input(
    placement_group_id: PlacementGroupId,
) -> Result<NodeGatewayMacOsSafetyInput, NodeGatewayApiError> {
    NodeGatewayMacOsSafetyInput::new(
        placement_group_id.clone(),
        vec![NodeGatewayMacOsPlacement::new(
            placement(placement_group_id),
            Sha256Digest::parse(&identity('a', 64)).expect("plan"),
        )],
    )
}

// Returns one bounded non-secret bearer fixture.
fn bearer() -> NodeGatewayBearer {
    NodeGatewayBearer::parse("li_fixture_bearer").expect("bearer")
}

// Round-trips one nested local Gateway request through schema-versioned transport.
fn round_trip_request(request: NodeGatewayRequest) -> NodeGatewayRequest {
    let envelope = NodePrivateTransportRequest::new(
        Sha256Digest::parse(&identity('b', 64)).expect("request"),
        NodePrivateRequest::Gateway(request),
    );
    let document = NodePrivateTransport::encode_request(&envelope).expect("encode request");
    let decoded = NodePrivateTransport::decode_request(&document).expect("decode request");
    let NodePrivateRequest::Gateway(request) = decoded.into_request() else {
        panic!("Gateway request");
    };
    request
}

// Round-trips one nested local Gateway response through schema-versioned transport.
fn round_trip_response(response: NodeGatewayResponse) -> NodeGatewayResponse {
    let envelope = NodePrivateTransportResponse::new(
        Sha256Digest::parse(&identity('c', 64)).expect("request"),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Gateway(response)),
    );
    let document = NodePrivateTransport::encode_response(&envelope).expect("encode response");
    let decoded = NodePrivateTransport::decode_response(&document).expect("decode response");
    let NodePrivateTransportOutcome::Success(NodePrivateResponse::Gateway(response)) =
        decoded.outcome()
    else {
        panic!("Gateway response");
    };
    response.clone()
}

// Proves main and child dispatch expose only their exact eight-capability role matrix.
#[test]
fn gateway_api_enforces_roles_and_maps_all_atomic_capabilities() {
    let capabilities = Arc::new(GatewayCapabilities::ordinary());
    let api = NodeGatewayApi::new(capabilities.clone());
    let group = route().placement_group_id().clone();
    let main_requests = [
        NodeGatewayRequest::AuthorizeInference {
            bearer: bearer(),
            model: model(),
        },
        NodeGatewayRequest::AuthorizeModelList { bearer: bearer() },
        NodeGatewayRequest::ReadRoutes { model: model() },
        NodeGatewayRequest::ResolveNativeTarget { route: route() },
        NodeGatewayRequest::ReadRecentUsage {
            key_id: principal().key_id().clone(),
            since: UnixMilliseconds::new(0),
        },
        NodeGatewayRequest::RecordUsage { usage: usage() },
        NodeGatewayRequest::ReadMacOsSafetyInput {
            placement_group_id: group.clone(),
        },
    ];
    for request in main_requests {
        api.dispatch(NodeRole::Main, request)
            .expect("main capability");
    }
    assert_eq!(
        api.dispatch(
            NodeRole::Main,
            NodeGatewayRequest::AuthorizeInboundRelay { bearer: bearer() }
        ),
        Err(NodeGatewayApiError::RoleDenied)
    );
    assert!(matches!(
        api.dispatch(
            NodeRole::Child,
            NodeGatewayRequest::AuthorizeInboundRelay { bearer: bearer() }
        ),
        Ok(NodeGatewayResponse::RelayPrincipal(_))
    ));
    for request in [
        NodeGatewayRequest::ReadRoutes { model: model() },
        NodeGatewayRequest::ResolveNativeTarget { route: route() },
        NodeGatewayRequest::ReadMacOsSafetyInput {
            placement_group_id: group,
        },
    ] {
        api.dispatch(NodeRole::Child, request)
            .expect("shared child capability");
    }
    assert_eq!(
        api.dispatch(
            NodeRole::Child,
            NodeGatewayRequest::AuthorizeInference {
                bearer: bearer(),
                model: model(),
            }
        ),
        Err(NodeGatewayApiError::RoleDenied)
    );
    assert_eq!(capabilities.calls.lock().expect("calls").len(), 11);
}

// Proves authorization, replay, redaction, and provider-output bounds stay explicit.
#[test]
fn gateway_api_maps_denial_replay_and_bounds_without_secret_output() {
    let capabilities = Arc::new(GatewayCapabilities::ordinary());
    let api = NodeGatewayApi::new(capabilities);
    assert_eq!(
        api.dispatch(
            NodeRole::Main,
            NodeGatewayRequest::AuthorizeInference {
                bearer: NodeGatewayBearer::parse("denied").expect("bearer"),
                model: model(),
            }
        ),
        Err(NodeGatewayApiError::AuthorizationDenied)
    );
    assert_eq!(
        api.dispatch(
            NodeRole::Main,
            NodeGatewayRequest::RecordUsage { usage: usage() }
        ),
        Ok(NodeGatewayResponse::UsageRecorded(
            NodeGatewayUsageDisposition::Replayed
        ))
    );
    assert!(!format!("{:?}", bearer()).contains("li_fixture_bearer"));
    assert_eq!(
        NodeGatewayBearer::parse(&"x".repeat(513)),
        Err(NodeGatewayApiError::InvalidContract)
    );
    let oversized = NodeGatewayApi::new(Arc::new(GatewayCapabilities {
        calls: Mutex::new(Vec::new()),
        route_count: NODE_GATEWAY_MAXIMUM_ROUTES + 1,
    }));
    assert_eq!(
        oversized.dispatch(
            NodeRole::Main,
            NodeGatewayRequest::ReadRoutes { model: model() }
        ),
        Err(NodeGatewayApiError::InvalidContract)
    );
}

// Proves every request and response variant has one exact closed codec representation.
#[test]
fn gateway_transport_round_trips_all_variants_and_rejects_mutations() {
    let group = route().placement_group_id().clone();
    let requests = vec![
        NodeGatewayRequest::AuthorizeInference {
            bearer: bearer(),
            model: model(),
        },
        NodeGatewayRequest::AuthorizeModelList { bearer: bearer() },
        NodeGatewayRequest::ReadRoutes { model: model() },
        NodeGatewayRequest::ResolveNativeTarget { route: route() },
        NodeGatewayRequest::AuthorizeInboundRelay { bearer: bearer() },
        NodeGatewayRequest::ReadRecentUsage {
            key_id: principal().key_id().clone(),
            since: UnixMilliseconds::new(500),
        },
        NodeGatewayRequest::RecordUsage { usage: usage() },
        NodeGatewayRequest::ReadMacOsSafetyInput {
            placement_group_id: group.clone(),
        },
    ];
    for request in requests {
        assert_eq!(round_trip_request(request.clone()), request);
    }
    let responses = vec![
        NodeGatewayResponse::Principal(principal()),
        NodeGatewayResponse::ModelScope(ApiKeyModelScope::selected(vec![model()]).expect("scope")),
        NodeGatewayResponse::Routes(vec![route()]),
        NodeGatewayResponse::NativeTarget(native_target()),
        NodeGatewayResponse::RelayPrincipal(node_id('2')),
        NodeGatewayResponse::UsageRecords(vec![usage()]),
        NodeGatewayResponse::UsageRecorded(NodeGatewayUsageDisposition::Applied),
        NodeGatewayResponse::MacOsSafetyInput(macos_input(group).expect("macOS input")),
    ];
    for response in responses {
        assert_eq!(round_trip_response(response.clone()), response);
    }

    let envelope = NodePrivateTransportRequest::new(
        Sha256Digest::parse(&identity('d', 64)).expect("request"),
        NodePrivateRequest::Gateway(NodeGatewayRequest::AuthorizeModelList { bearer: bearer() }),
    );
    let document = NodePrivateTransport::encode_request(&envelope).expect("encode");
    let mut mutation: serde_json::Value = serde_json::from_slice(&document).expect("JSON");
    mutation["request"]["arguments"]["arguments"]["unexpected"] = serde_json::json!(true);
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&mutation).expect("mutation")
    )
    .is_err());
    mutation = serde_json::from_slice(&document).expect("JSON");
    mutation["schema"]["version"] = serde_json::json!(1);
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&mutation).expect("mutation")
    )
    .is_err());
    mutation = serde_json::from_slice(&document).expect("JSON");
    mutation["request"]["arguments"]["arguments"]["bearer"] = serde_json::json!("unsafe bearer");
    assert!(NodePrivateTransport::decode_request(
        &serde_json::to_vec(&mutation).expect("mutation")
    )
    .is_err());

    let response = NodePrivateTransportResponse::new(
        Sha256Digest::parse(&identity('f', 64)).expect("request"),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Gateway(
            NodeGatewayResponse::Routes(vec![route()]),
        )),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("encode response");
    mutation = serde_json::from_slice(&document).expect("JSON");
    let route_value = mutation["response"]["value"]["value"][0].clone();
    mutation["response"]["value"]["value"] =
        serde_json::Value::Array(vec![route_value; NODE_GATEWAY_MAXIMUM_ROUTES + 1]);
    let document = serde_json::to_vec(&mutation).expect("mutation");
    assert!(document.len() < 1024 * 1024);
    assert!(NodePrivateTransport::decode_response(&document).is_err());

    let response = NodePrivateTransportResponse::new(
        Sha256Digest::parse(&identity('1', 64)).expect("request"),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Gateway(
            NodeGatewayResponse::NativeTarget(native_target()),
        )),
    );
    let document = NodePrivateTransport::encode_response(&response).expect("encode response");
    mutation = serde_json::from_slice(&document).expect("JSON");
    mutation["response"]["value"]["value"]["expected_server_leaf_sha256"] =
        serde_json::json!(identity('2', 64));
    assert!(NodePrivateTransport::decode_response(
        &serde_json::to_vec(&mutation).expect("mutation")
    )
    .is_err());
}

// Proves every typed provider failure maps to one stable redacted transport code.
#[test]
fn gateway_transport_maps_the_closed_error_contract() {
    let cases = [
        (
            NodeGatewayApiError::AuthorizationDenied,
            "gateway_authorization_denied",
        ),
        (NodeGatewayApiError::RoleDenied, "gateway_role_denied"),
        (
            NodeGatewayApiError::InvalidContract,
            "gateway_contract_invalid",
        ),
        (
            NodeGatewayApiError::ReplayConflict,
            "gateway_replay_conflict",
        ),
        (NodeGatewayApiError::CorruptState, "gateway_state_corrupt"),
        (NodeGatewayApiError::Unavailable, "gateway_unavailable"),
    ];
    for (failure, expected_code) in cases {
        let document = NodePrivateTransport::encode_dispatch_result(
            Sha256Digest::parse(&identity('e', 64)).expect("request"),
            Err(NodePrivateApiError::Gateway(failure)),
        )
        .expect("encode failure");
        let response = NodePrivateTransport::decode_response(&document).expect("decode failure");
        let NodePrivateTransportOutcome::Failure(error) = response.outcome() else {
            panic!("Gateway failure");
        };
        assert_eq!(error.code().as_str(), expected_code);
        assert!(!error.message().is_empty());
    }
}
