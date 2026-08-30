// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_cli::{
    NativeChildLifecyclePort, NodePrivateClient, NodePrivateClientConfiguration,
    NodePrivateDocumentExchangeError, NodePrivateDocumentExchangePort, NodeRequestIdentityError,
    NodeRequestIdentitySource, PairedMainChildLifecycle,
};
use li_core_interface::{
    DisplayName, EntityTimestamps, InstallationId, MachineId, Node, NodeAddress, NodeId,
    NodeIdentity, NodeRole, NodeState, Sha256Digest, UnixMilliseconds,
};
use li_node_manager::{
    NodePrivateRequest, NodePrivateTransport, NodePrivateTransportOutcome,
    NodePrivateTransportResponse, NodeTransition,
};

// Returns fresh deterministic transport identities without opening system entropy.
struct IdentitySource {
    values: VecDeque<Sha256Digest>,
}

impl NodeRequestIdentitySource for IdentitySource {
    // Returns the next exact correlation identity.
    fn next_request_id(&mut self) -> Result<Sha256Digest, NodeRequestIdentityError> {
        self.values
            .pop_front()
            .ok_or(NodeRequestIdentityError::Unavailable)
    }
}

// Serves one main-owned child read and transition through the real private v1 codec.
struct LifecycleExchange {
    before: Node,
    after: Node,
    requests: Arc<Mutex<Vec<NodePrivateRequest>>>,
}

impl NodePrivateDocumentExchangePort for LifecycleExchange {
    // Records exact requests and returns versioned Node documents with no direct manager access.
    fn exchange(
        &mut self,
        request: &[u8],
        _timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, NodePrivateDocumentExchangeError> {
        let request = NodePrivateTransport::decode_request(request)
            .map_err(|_| NodePrivateDocumentExchangeError::MalformedResponse)?;
        self.requests
            .lock()
            .expect("requests")
            .push(request.request().clone());
        let response = match request.request() {
            NodePrivateRequest::ReadNode { node_id }
                if node_id == self.before.identity().node_id() =>
            {
                node_change_response(request.request_id(), &self.before, 7)
            }
            NodePrivateRequest::TransitionChild { node_id, .. }
                if node_id == self.before.identity().node_id() =>
            {
                node_change_response(request.request_id(), &self.after, 8)
            }
            _ => return Err(NodePrivateDocumentExchangeError::Unavailable),
        };
        if response.len() > maximum_response_bytes {
            return Err(NodePrivateDocumentExchangeError::ResponseTooLarge);
        }
        Ok(response)
    }
}

// Routes one child-local lifecycle command only through its main-owned optimistic record.
#[test]
fn paired_main_child_lifecycle_reads_then_transitions_exact_self() {
    let before = child(NodeState::Active, UnixMilliseconds::new(2_000));
    let after = child(NodeState::Draining, UnixMilliseconds::new(3_000));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let lifecycle = PairedMainChildLifecycle::new(NodePrivateClient::new(
        LifecycleExchange {
            before: before.clone(),
            after: after.clone(),
            requests: Arc::clone(&requests),
        },
        identities(),
        NodePrivateClientConfiguration::default(),
    ));

    assert_eq!(
        lifecycle.transition(&before, NodeTransition::Pause, UnixMilliseconds::new(3_000)),
        Ok(after)
    );
    let requests = requests.lock().expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0],
        NodePrivateRequest::ReadNode {
            node_id: before.identity().node_id().clone()
        }
    );
    let NodePrivateRequest::TransitionChild {
        node_id,
        expected_revision,
        transition,
        updated_at,
        idempotency_key,
    } = &requests[1]
    else {
        panic!("transition request");
    };
    assert_eq!(node_id, before.identity().node_id());
    assert_eq!(*expected_revision, 7);
    assert_eq!(*transition, NodeTransition::Pause);
    assert_eq!(*updated_at, UnixMilliseconds::new(3_000));
    assert!(idempotency_key.starts_with("li_cli_node_"));
}

// Encodes one versioned Node change without exposing NodeManager's internal constructor.
fn node_change_response(request_id: &Sha256Digest, node: &Node, revision: u64) -> Vec<u8> {
    let document = format!(
        "{{\"schema\":{{\"name\":\"li_node_private_api\",\"version\":2}},\"request_id\":\"{}\",\"response\":{{\"kind\":\"node_changed\",\"value\":{{\"node\":{{\"node_id\":\"{}\",\"machine_id\":\"{}\",\"installation_id\":\"{}\",\"display_name\":\"{}\",\"role\":\"child\",\"state\":\"{}\",\"control_address\":\"{}\",\"latest_hardware_observation_id\":null,\"created_at_unix_milliseconds\":{},\"updated_at_unix_milliseconds\":{}}},\"revision\":{},\"event\":null}}}}}}",
        request_id.as_str(),
        node.identity().node_id().as_str(),
        node.identity().machine_id().as_str(),
        node.identity().installation_id().as_str(),
        node.display_name().as_str(),
        match node.state() {
            NodeState::Active => "active",
            NodeState::Draining => "draining",
            _ => panic!("unsupported fixture state"),
        },
        node.control_address().as_str(),
        node.timestamps().created_at().value(),
        node.timestamps().updated_at().value(),
        revision,
    );
    let response =
        NodePrivateTransport::decode_response(document.as_bytes()).expect("versioned response");
    assert!(matches!(
        response.outcome(),
        NodePrivateTransportOutcome::Success(_)
    ));
    NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
        response.request_id().clone(),
        response.into_outcome(),
    ))
    .expect("canonical response")
}

// Returns one exact local child fixture.
fn child(state: NodeState, updated_at: UnixMilliseconds) -> Node {
    Node::new(
        NodeIdentity::new(
            NodeId::parse(&"2".repeat(32)).expect("node"),
            MachineId::parse(&"3".repeat(32)).expect("machine"),
            InstallationId::parse(&"4".repeat(64)).expect("installation"),
        ),
        DisplayName::parse("homeai-node-2").expect("name"),
        NodeRole::Child,
        state,
        NodeAddress::parse("homeai-node-2.local").expect("address"),
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), updated_at).expect("timestamps"),
    )
}

// Returns the two exact request correlation identities used by one lifecycle.
fn identities() -> IdentitySource {
    IdentitySource {
        values: VecDeque::from([
            Sha256Digest::parse(&"a".repeat(64)).expect("read identity"),
            Sha256Digest::parse(&"b".repeat(64)).expect("transition identity"),
        ]),
    }
}
