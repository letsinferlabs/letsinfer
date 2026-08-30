// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use li_core_interface::{
    CredentialId, DeviceId, EndpointAddress, EndpointHealth, EndpointOwnership, EndpointScheme,
    EngineDistribution, EntityTimestamps, InterconnectKind, InterconnectRequirement,
    LogicalModelName, ModelServiceDesiredState, ModelServiceId, NetworkPort, NodeAddress, NodeId,
    Placement, PlacementAssignment, PlacementEndpoint, PlacementGroup, PlacementGroupCapacity,
    PlacementGroupId, PlacementGroupState, PlacementId, PlacementResources, PlacementState,
    PortRange, ResourceIdentity, ResourceLease, ResourceLeaseId, ResourceLeaseState,
    RuntimeCandidateId, RuntimeIdentity, RuntimeInstallationId, RuntimeSource, RuntimeVersion,
    Sha256Digest, TargetId, TaskId, TokenCountContract, TokenCountProtocol, UnixMilliseconds,
};
use li_gateway_manager::{
    GatewayNativeIoError, GatewayNativeTarget, GatewayNativeTargetProvider, GatewayRoute,
    GatewayRouteTarget,
};
use li_node_manager::{
    GatewayPlacementRecordProvider, NodeGatewayNativeTargetProvider, NodeGatewayRelayTarget,
    NodeGatewayRelayTargetProvider,
};
use li_placement_manager::{
    PlacementCredentialReader, PlacementCredentialReferences, PlacementError, PlacementRecord,
};

// Returns one exact runtime identity for native-target fixtures.
fn runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity::new(
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").unwrap(),
        RuntimeVersion::parse("1.0.0").unwrap(),
        TargetId::parse("dgx-spark").unwrap(),
        RuntimeSource::parse(&format!("ghcr.io/runtime/qwen@sha256:{}", "a".repeat(64))).unwrap(),
        EngineDistribution::oci(
            RuntimeSource::parse(&format!("ghcr.io/engine/qwen@sha256:{}", "b".repeat(64)))
                .unwrap(),
            Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            None,
            Some(Sha256Digest::parse(&"d".repeat(64)).unwrap()),
        ),
        Sha256Digest::parse(&"a".repeat(64)).unwrap(),
        Sha256Digest::parse(&"e".repeat(64)).unwrap(),
        Sha256Digest::parse(&"f".repeat(64)).unwrap(),
    )
    .unwrap()
}

// Returns one complete running aggregate on the selected endpoint node.
fn running_record(node_id: &str, endpoint_host: &str) -> PlacementRecord {
    let node_id = NodeId::parse(node_id).unwrap();
    let service_id = ModelServiceId::parse(&"4".repeat(32)).unwrap();
    let group_id = PlacementGroupId::parse(&"5".repeat(32)).unwrap();
    let placement_id = PlacementId::parse(&"6".repeat(32)).unwrap();
    let device_id = DeviceId::parse("GPU-A").unwrap();
    let resources = PlacementResources::new(
        PortRange::new(18_000, 1).unwrap(),
        vec![device_id.clone()],
        None,
    )
    .unwrap();
    let placement = Placement::new(
        placement_id.clone(),
        group_id.clone(),
        PlacementAssignment::new(
            node_id.clone(),
            RuntimeInstallationId::parse(&"2".repeat(32)).unwrap(),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32)).unwrap(),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").unwrap(),
            UnixMilliseconds::new(900),
            TaskId::parse("task-0").unwrap(),
            NodeAddress::parse(endpoint_host).unwrap(),
            resources,
            EndpointOwnership::Owner,
        ),
        PlacementState::Running,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000)).unwrap(),
    )
    .unwrap();
    let endpoint = PlacementEndpoint::new(
        placement_id.clone(),
        node_id.clone(),
        EndpointAddress::new(
            EndpointScheme::Https,
            NodeAddress::parse(endpoint_host).unwrap(),
            18_000,
        )
        .unwrap(),
        CredentialId::parse(&"3".repeat(32)).unwrap(),
        Some(CredentialId::parse(&"8".repeat(32)).unwrap()),
        Some(TokenCountContract::new("/li/token-count", TokenCountProtocol::LetsInferV1).unwrap()),
        4,
        262_144,
        EndpointHealth::new(true, false, Some(52_000), Vec::new()).unwrap(),
    )
    .unwrap();
    let group = PlacementGroup::new(
        group_id,
        service_id,
        runtime_identity(),
        vec![placement_id.clone()],
        placement_id.clone(),
        Some(endpoint),
        PlacementGroupCapacity::new(
            8,
            4,
            262_144,
            InterconnectRequirement::new(InterconnectKind::Any, false, 0, 0),
        )
        .unwrap(),
        ModelServiceDesiredState::Running,
        PlacementGroupState::Running,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000)).unwrap(),
    )
    .unwrap();
    let leases = [
        ResourceIdentity::Accelerator(device_id),
        ResourceIdentity::Port(NetworkPort::new(18_000).unwrap()),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, resource)| {
        ResourceLease::new(
            ResourceLeaseId::parse(&format!("{:032x}", 7 + index)).unwrap(),
            placement_id.clone(),
            node_id.clone(),
            resource,
            ResourceLeaseState::Active,
            EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(2_000))
                .unwrap(),
        )
    })
    .collect();
    PlacementRecord::new(
        group,
        vec![placement],
        leases,
        vec![vec![placement_id.clone()]],
        vec![(placement_id, Sha256Digest::parse(&"9".repeat(64)).unwrap())],
    )
    .unwrap()
}

// Supplies one mutable placement aggregate or explicit absence.
struct RecordMock {
    record: Mutex<Option<PlacementRecord>>,
}

impl GatewayPlacementRecordProvider for RecordMock {
    // Returns the configured aggregate only when its group identity matches.
    fn record(
        &self,
        placement_group_id: &PlacementGroupId,
    ) -> Result<Option<PlacementRecord>, GatewayNativeIoError> {
        Ok(self
            .record
            .lock()
            .unwrap()
            .clone()
            .filter(|record| record.group().placement_group_id() == placement_group_id))
    }
}

// Supplies one existing credential reference set without secret bytes.
struct CredentialMock {
    references: Mutex<Option<PlacementCredentialReferences>>,
}

impl PlacementCredentialReader for CredentialMock {
    // Returns the configured reference-only placement credentials.
    fn existing(
        &self,
        _placement: &Placement,
    ) -> Result<Option<PlacementCredentialReferences>, PlacementError> {
        Ok(self.references.lock().unwrap().clone())
    }
}

// Records the exact child relay identity and returns one fixed native target.
struct RelayMock {
    calls: Mutex<Vec<(String, String, String, Option<String>)>>,
    target: NodeGatewayRelayTarget,
}

impl NodeGatewayRelayTargetProvider for RelayMock {
    // Records one exact group, node, address, and token-count path.
    fn target(
        &self,
        placement_group_id: &PlacementGroupId,
        child_node_id: &NodeId,
        address: &NodeAddress,
        token_count: Option<TokenCountContract>,
    ) -> Result<NodeGatewayRelayTarget, GatewayNativeIoError> {
        self.calls.lock().unwrap().push((
            placement_group_id.as_str().to_string(),
            child_node_id.as_str().to_string(),
            address.as_str().to_string(),
            token_count.map(|value| value.path().to_string()),
        ));
        Ok(self.target.clone())
    }
}

// Returns the reference-only credential fixture for one endpoint placement.
fn references(credential_id: &str) -> PlacementCredentialReferences {
    PlacementCredentialReferences::new(
        PlacementId::parse(&"6".repeat(32)).unwrap(),
        CredentialId::parse(credential_id).unwrap(),
        CredentialId::parse(&"8".repeat(32)).unwrap(),
        PathBuf::from("/private/placement/li_engine_credential"),
        PathBuf::from("/private/placement/li_engine_tls_certificate.pem"),
        PathBuf::from("/private/placement/li_engine_tls_private_key.pem"),
        Sha256Digest::parse(&"a".repeat(64)).unwrap(),
        Sha256Digest::parse(&"b".repeat(64)).unwrap(),
    )
    .unwrap()
}

// Creates one route matching the supplied placement aggregate and target.
fn route(record: &PlacementRecord, target: GatewayRouteTarget) -> GatewayRoute {
    let endpoint = record.group().endpoint().unwrap();
    GatewayRoute::new(
        record.group().placement_group_id().clone(),
        endpoint.node_id().clone(),
        LogicalModelName::parse("qwen3_8").unwrap(),
        target,
        NonZeroU32::new(endpoint.max_active_requests()).unwrap(),
        NonZeroU64::new(endpoint.max_context_tokens()).unwrap(),
        true,
        false,
        None,
        Vec::new(),
    )
    .unwrap()
}

// Creates one inert relay target used when the local branch must not call it.
fn relay_target() -> GatewayNativeTarget {
    GatewayNativeTarget::child_relay(
        "child.local",
        8_443,
        501,
        PathBuf::from("/private/relay/bearer"),
        PathBuf::from("/private/relay/ca.pem"),
        Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        PathBuf::from("/private/relay/client.pem"),
        PathBuf::from("/private/relay/client.key"),
        Some(TokenCountContract::new("/li/token-count", TokenCountProtocol::LetsInferV1).unwrap()),
    )
    .unwrap()
}

// Returns one relay result carrying the future exact child server-leaf pin.
fn relay_binding() -> NodeGatewayRelayTarget {
    NodeGatewayRelayTarget::new(
        relay_target(),
        NodeId::parse(&"2".repeat(32)).unwrap(),
        NodeAddress::parse("child.local").unwrap(),
        CredentialId::parse(&"c".repeat(32)).unwrap(),
        PathBuf::from("/private/relay/child.pem"),
        Sha256Digest::parse(&"d".repeat(64)).unwrap(),
    )
    .unwrap()
}

// Proves a local route resolves exact endpoint-owned bearer, CA, and token-count references.
#[test]
fn local_engine_target_uses_exact_placement_credentials() {
    let record = running_record(&"1".repeat(32), "127.0.0.1");
    let expected = GatewayNativeTarget::local_engine(
        record.group().endpoint().unwrap().address(),
        501,
        PathBuf::from("/private/placement/li_engine_credential"),
        PathBuf::from("/private/placement/li_engine_tls_certificate.pem"),
        record.group().endpoint().unwrap().token_count().cloned(),
    )
    .unwrap();
    let relay = Arc::new(RelayMock {
        calls: Mutex::new(Vec::new()),
        target: relay_binding(),
    });
    let provider = NodeGatewayNativeTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).unwrap(),
        501,
        Arc::new(RecordMock {
            record: Mutex::new(Some(record.clone())),
        }),
        Arc::new(CredentialMock {
            references: Mutex::new(Some(references(&"3".repeat(32)))),
        }),
        relay.clone(),
    );
    let selected = route(
        &record,
        GatewayRouteTarget::LocalEngine {
            endpoint: record.group().endpoint().unwrap().address().clone(),
        },
    );

    assert_eq!(provider.target(&selected).unwrap(), expected);
    assert!(relay.calls.lock().unwrap().is_empty());
}

// Proves a remote route delegates only exact child identity and endpoint-owned token contract.
#[test]
fn child_route_uses_node_owned_relay_trust() {
    let child_id = "2".repeat(32);
    let record = running_record(&child_id, "127.0.0.1");
    let expected = relay_target();
    let relay = Arc::new(RelayMock {
        calls: Mutex::new(Vec::new()),
        target: relay_binding(),
    });
    let provider = NodeGatewayNativeTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).unwrap(),
        501,
        Arc::new(RecordMock {
            record: Mutex::new(Some(record.clone())),
        }),
        Arc::new(CredentialMock {
            references: Mutex::new(None),
        }),
        relay.clone(),
    );
    let selected = route(
        &record,
        GatewayRouteTarget::ChildRelay {
            address: NodeAddress::parse("child.local").unwrap(),
        },
    );

    assert_eq!(provider.target(&selected).unwrap(), expected);
    assert_eq!(
        relay.calls.lock().unwrap().as_slice(),
        [(
            "5".repeat(32),
            child_id,
            "child.local".to_string(),
            Some("/li/token-count".to_string()),
        )]
    );
}

// Proves missing, changed, or foreign local route bindings fail before native file reads.
#[test]
fn native_target_binding_matrix_fails_closed() {
    let record = running_record(&"1".repeat(32), "127.0.0.1");
    let relay = Arc::new(RelayMock {
        calls: Mutex::new(Vec::new()),
        target: relay_binding(),
    });
    let missing = NodeGatewayNativeTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).unwrap(),
        501,
        Arc::new(RecordMock {
            record: Mutex::new(None),
        }),
        Arc::new(CredentialMock {
            references: Mutex::new(None),
        }),
        relay.clone(),
    );
    let selected = route(
        &record,
        GatewayRouteTarget::LocalEngine {
            endpoint: record.group().endpoint().unwrap().address().clone(),
        },
    );
    assert!(missing.target(&selected).is_err());

    let no_credentials = NodeGatewayNativeTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).unwrap(),
        501,
        Arc::new(RecordMock {
            record: Mutex::new(Some(record.clone())),
        }),
        Arc::new(CredentialMock {
            references: Mutex::new(None),
        }),
        relay.clone(),
    );
    assert!(no_credentials.target(&selected).is_err());

    let wrong_credentials = NodeGatewayNativeTargetProvider::new(
        NodeId::parse(&"1".repeat(32)).unwrap(),
        501,
        Arc::new(RecordMock {
            record: Mutex::new(Some(record.clone())),
        }),
        Arc::new(CredentialMock {
            references: Mutex::new(Some(references(&"7".repeat(32)))),
        }),
        relay.clone(),
    );
    assert!(wrong_credentials.target(&selected).is_err());

    let changed_endpoint = route(
        &record,
        GatewayRouteTarget::LocalEngine {
            endpoint: EndpointAddress::new(
                EndpointScheme::Https,
                NodeAddress::parse("127.0.0.2").unwrap(),
                18_000,
            )
            .unwrap(),
        },
    );
    assert!(wrong_credentials.target(&changed_endpoint).is_err());

    let foreign = NodeGatewayNativeTargetProvider::new(
        NodeId::parse(&"2".repeat(32)).unwrap(),
        501,
        Arc::new(RecordMock {
            record: Mutex::new(Some(record)),
        }),
        Arc::new(CredentialMock {
            references: Mutex::new(Some(references(&"3".repeat(32)))),
        }),
        relay,
    );
    assert!(foreign.target(&selected).is_err());
}
