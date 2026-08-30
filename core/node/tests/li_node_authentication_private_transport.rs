// SPDX-License-Identifier: AGPL-3.0-only

use std::num::{NonZeroU32, NonZeroU64};

use li_authentication_manager::{
    ApiKey, ApiKeyLimits, ApiKeyModelScope, ApiKeyPolicy, ControllerPublicKey, ControllerRole,
    ControllerState,
};
use li_core_interface::{
    ApiKeyId, ControllerId, DisplayName, LogicalModelName, Sha256Digest, TechnicalName,
    UnixMilliseconds,
};
use li_node_manager::{
    NodeApiKeyPolicyUpdate, NodeControllerEnrollmentCandidate, NodeControllerSummary,
    NodeIssuedApiKey, NodePrivateRequest, NodePrivateResponse, NodePrivateTransport,
    NodePrivateTransportError, NodePrivateTransportOutcome, NodePrivateTransportRequest,
    NodePrivateTransportResponse, NODE_PRIVATE_MAX_DOCUMENT_BYTES,
};

// Returns one fixed correlation identity.
fn request_id() -> Sha256Digest {
    Sha256Digest::parse(&"1".repeat(64)).expect("request")
}

// Returns one exact API-key identity-bound token.
fn token() -> String {
    format!("li_{}_{}", "a".repeat(32), "b".repeat(64))
}

// Returns one complete selected-model policy fixture.
fn policy() -> ApiKeyPolicy {
    ApiKeyPolicy::new(
        ApiKeyModelScope::selected(vec![LogicalModelName::parse("qwen3.8").expect("model")])
            .expect("scope"),
        Some(UnixMilliseconds::new(9_000)),
        ApiKeyLimits::new(
            NonZeroU32::new(60),
            NonZeroU64::new(60_000),
            NonZeroU32::new(4),
            NonZeroU64::new(32_768),
        ),
        Some(TechnicalName::parse("tenant_a").expect("tenant")),
        Some(TechnicalName::parse("chat").expect("application")),
    )
}

// Returns one complete non-secret API-key metadata fixture.
fn api_key() -> ApiKey {
    ApiKey::new(
        ApiKeyId::parse(&"a".repeat(32)).expect("key"),
        DisplayName::parse("Application").expect("name"),
        policy(),
        UnixMilliseconds::new(1_000),
        None,
        None,
    )
    .expect("API key")
}

// Returns one complete secret-free active controller fixture.
fn controller() -> NodeControllerSummary {
    NodeControllerSummary::restore(
        ControllerId::parse(&"c".repeat(32)).expect("controller"),
        DisplayName::parse("Desk Mac").expect("controller name"),
        ControllerRole::Administrator,
        ControllerState::Active,
        Sha256Digest::parse(&"d".repeat(64)).expect("certificate"),
        Sha256Digest::parse(&"e".repeat(64)).expect("public key"),
        UnixMilliseconds::new(0),
        UnixMilliseconds::new(10_000),
        UnixMilliseconds::new(1_000),
        Some(UnixMilliseconds::new(1_000)),
        None,
    )
    .expect("controller summary")
}

// Returns one proof-validated public controller candidate.
fn controller_candidate() -> NodeControllerEnrollmentCandidate {
    NodeControllerEnrollmentCandidate::new(
        ControllerId::parse(&"c".repeat(32)).expect("controller"),
        DisplayName::parse("Desk Mac").expect("controller name"),
        ControllerPublicKey::new(vec![7; 96]).expect("public key"),
    )
}

// Round-trips every authentication action through the closed typed wire codec.
#[test]
fn wire_roundtrips_every_authentication_request_without_secret_fields() {
    let requests = [
        NodePrivateRequest::AddController {
            candidate: controller_candidate(),
            role: ControllerRole::Administrator,
        },
        NodePrivateRequest::ReadControllers,
        NodePrivateRequest::RevokeController {
            selector: "Desk Mac".to_string(),
        },
        NodePrivateRequest::CreateApiKey {
            name: DisplayName::parse("Application").expect("name"),
            policy: policy(),
        },
        NodePrivateRequest::ReadApiKeys,
        NodePrivateRequest::ReadApiKey {
            selector: "Application".to_string(),
        },
        NodePrivateRequest::UpdateApiKeyPolicy {
            selector: "Application".to_string(),
            update: NodeApiKeyPolicyUpdate::new(
                Some(vec![LogicalModelName::parse("deepseek_r1").expect("model")]),
                Some(UnixMilliseconds::new(10_000)),
                None,
                None,
                Some(NonZeroU32::new(8).expect("concurrency")),
                None,
                None,
                Some(TechnicalName::parse("assistant").expect("application")),
            ),
        },
        NodePrivateRequest::RotateApiKey {
            selector: "Application".to_string(),
        },
        NodePrivateRequest::RevokeApiKey {
            selector: "Application".to_string(),
        },
    ];
    for request in requests {
        let envelope = NodePrivateTransportRequest::new(request_id(), request.clone());
        let encoded = NodePrivateTransport::encode_request(&envelope).expect("encode");
        let document = String::from_utf8_lossy(&encoded);
        assert!(!document.contains("\"token\":"));
        assert!(!document.contains("certificate_public_material"));
        assert!(!document.contains("private_key"));
        let decoded = NodePrivateTransport::decode_request(&encoded).expect("decode");
        assert_eq!(decoded.request(), &request);
    }
}

// Transfers the issued token through one response encoding and rejects a second presentation.
#[test]
fn wire_presents_an_issued_token_once_and_redacts_every_debug_projection() {
    let secret = token();
    let response = NodePrivateTransportResponse::new(
        request_id(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::ApiKeyIssued(
            NodeIssuedApiKey::new(api_key(), secret.clone()),
        )),
    );
    let debug_before = format!("{response:?}");
    assert!(debug_before.contains("<redacted>"));
    assert!(!debug_before.contains(&secret));
    let encoded = NodePrivateTransport::encode_response(&response).expect("first encode");
    assert_eq!(
        String::from_utf8_lossy(&encoded).matches(&secret).count(),
        1
    );
    assert_eq!(
        NodePrivateTransport::encode_response(&response).expect_err("second encode"),
        NodePrivateTransportError::InvalidDocument {
            reason: "issued API-key token was already consumed"
        }
    );
    let decoded = NodePrivateTransport::decode_response(&encoded).expect("decode");
    let NodePrivateTransportOutcome::Success(NodePrivateResponse::ApiKeyIssued(issued)) =
        decoded.outcome()
    else {
        panic!("issued response");
    };
    assert_eq!(issued.take_token().as_deref(), Some(secret.as_str()));
    assert!(issued.take_token().is_none());
    assert!(!format!("{decoded:?}").contains(&secret));
}

// Round-trips secret-free list, detail, update, and revocation response projections.
#[test]
fn wire_roundtrips_every_non_secret_authentication_response() {
    for response in [
        NodePrivateResponse::Controller(controller()),
        NodePrivateResponse::Controllers(vec![controller()]),
        NodePrivateResponse::ApiKeys(vec![api_key()]),
        NodePrivateResponse::ApiKey(api_key()),
    ] {
        let envelope = NodePrivateTransportResponse::new(
            request_id(),
            NodePrivateTransportOutcome::Success(response.clone()),
        );
        let encoded = NodePrivateTransport::encode_response(&envelope).expect("encode");
        let decoded = NodePrivateTransport::decode_response(&encoded).expect("decode");
        assert_eq!(
            decoded.outcome(),
            &NodePrivateTransportOutcome::Success(response)
        );
        assert!(!String::from_utf8_lossy(&encoded).contains("li_aaaaaaaa"));
        assert!(!String::from_utf8_lossy(&encoded).contains("certificate_public_material"));
        assert!(!String::from_utf8_lossy(&encoded).contains("private_key"));
    }
}

// Rejects unknown, missing, extra, invalid, truncated, and oversized auth documents closed.
#[test]
fn wire_rejects_authentication_document_mutations_without_echoing_values() {
    let valid = NodePrivateTransport::encode_request(&NodePrivateTransportRequest::new(
        request_id(),
        NodePrivateRequest::CreateApiKey {
            name: DisplayName::parse("Application").expect("name"),
            policy: policy(),
        },
    ))
    .expect("valid");
    let value: serde_json::Value = serde_json::from_slice(&valid).expect("JSON");
    let mut mutations = Vec::new();
    let mut unknown = value.clone();
    unknown["request"]["action"] = serde_json::json!("create_root_key");
    mutations.push(serde_json::to_vec(&unknown).expect("unknown"));
    let mut missing = value.clone();
    missing["request"]["arguments"]
        .as_object_mut()
        .expect("arguments")
        .remove("name");
    mutations.push(serde_json::to_vec(&missing).expect("missing"));
    let mut extra = value.clone();
    extra["request"]["arguments"]["plaintext_secret"] = serde_json::json!("forbidden");
    mutations.push(serde_json::to_vec(&extra).expect("extra"));
    let mut zero = value.clone();
    zero["request"]["arguments"]["policy"]["concurrency"] = serde_json::json!(0);
    mutations.push(serde_json::to_vec(&zero).expect("zero"));
    let mut empty_selector = value.clone();
    empty_selector["request"] =
        serde_json::json!({"action": "read_api_key", "arguments": {"selector": ""}});
    mutations.push(serde_json::to_vec(&empty_selector).expect("selector"));
    mutations.push(valid[..valid.len() - 1].to_vec());

    for mutation in mutations {
        let error = NodePrivateTransport::decode_request(&mutation).expect_err("mutation");
        assert!(!error.to_string().contains("forbidden"));
        assert!(!error.to_string().contains("Application"));
    }
    assert_eq!(
        NodePrivateTransport::decode_request(&vec![b' '; NODE_PRIVATE_MAX_DOCUMENT_BYTES + 1])
            .expect_err("oversized"),
        NodePrivateTransportError::DocumentTooLarge
    );

    let valid_response = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
        request_id(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::ApiKey(api_key())),
    ))
    .expect("valid response");
    let response_value: serde_json::Value =
        serde_json::from_slice(&valid_response).expect("response JSON");
    let mut response_mutations = Vec::new();
    let mut unknown_response = response_value.clone();
    unknown_response["response"]["kind"] = serde_json::json!("root_key");
    response_mutations.push(serde_json::to_vec(&unknown_response).expect("unknown response"));
    let mut missing_response = response_value.clone();
    missing_response["response"]
        .as_object_mut()
        .expect("response")
        .remove("value");
    response_mutations.push(serde_json::to_vec(&missing_response).expect("missing response"));
    let mut extra_response = response_value;
    extra_response["response"]["value"]["plaintext_secret"] =
        serde_json::json!("forbidden response secret");
    response_mutations.push(serde_json::to_vec(&extra_response).expect("extra response"));
    response_mutations.push(valid_response[..valid_response.len() - 1].to_vec());

    for mutation in response_mutations {
        let error = NodePrivateTransport::decode_response(&mutation).expect_err("mutation");
        assert!(!error.to_string().contains("forbidden response secret"));
        assert!(!error.to_string().contains("Application"));
    }
    assert_eq!(
        NodePrivateTransport::decode_response(&vec![b' '; NODE_PRIVATE_MAX_DOCUMENT_BYTES + 1])
            .expect_err("oversized response"),
        NodePrivateTransportError::DocumentTooLarge
    );
}

// Rejects an issued response whose token identity or one-time marker is mutated.
#[test]
fn wire_rejects_issued_token_identity_and_marker_mutations() {
    for (token_value, shown_once) in [
        (format!("li_{}_{}", "c".repeat(32), "b".repeat(64)), true),
        (token(), false),
        (format!("li_{}_{}", "a".repeat(32), "B".repeat(64)), true),
    ] {
        let document = serde_json::json!({
            "schema": {"name": "li_node_private_api", "version": 2},
            "request_id": "1".repeat(64),
            "response": {
                "kind": "api_key_issued",
                "value": {
                    "key": {
                        "key_id": "a".repeat(32), "name": "Application",
                        "policy": {
                            "selected_models": null, "expires_at_unix_milliseconds": null,
                            "requests_per_minute": null, "tokens_per_minute": null,
                            "concurrency": null, "context_tokens": null,
                            "tenant": null, "application": null
                        },
                        "created_at_unix_milliseconds": 1000,
                        "revoked_at_unix_milliseconds": null, "rotated_from": null
                    },
                    "token": token_value,
                    "token_shown_once": shown_once
                }
            }
        });
        assert!(NodePrivateTransport::decode_response(
            &serde_json::to_vec(&document).expect("document")
        )
        .is_err());
    }
}

// Rejects malformed controller roles, bounds, selectors, lifecycle, and secret-shaped fields.
#[test]
fn wire_rejects_controller_document_mutations_closed() {
    let request = NodePrivateTransport::encode_request(&NodePrivateTransportRequest::new(
        request_id(),
        NodePrivateRequest::AddController {
            candidate: controller_candidate(),
            role: ControllerRole::Administrator,
        },
    ))
    .expect("controller request");
    let value: serde_json::Value = serde_json::from_slice(&request).expect("request JSON");
    let mut invalid_key = value.clone();
    invalid_key["request"]["arguments"]["public_key_base64"] = serde_json::json!("bad");
    let mut invalid_role = value.clone();
    invalid_role["request"]["arguments"]["role"] = serde_json::json!("root");
    let mut private_key = value;
    private_key["request"]["arguments"]["private_key"] = serde_json::json!("forbidden");
    for mutation in [invalid_key, invalid_role, private_key] {
        let error = NodePrivateTransport::decode_request(
            &serde_json::to_vec(&mutation).expect("mutated request"),
        )
        .expect_err("controller request mutation");
        assert!(!error.to_string().contains("forbidden"));
    }

    let response = NodePrivateTransport::encode_response(&NodePrivateTransportResponse::new(
        request_id(),
        NodePrivateTransportOutcome::Success(NodePrivateResponse::Controller(controller())),
    ))
    .expect("controller response");
    let value: serde_json::Value = serde_json::from_slice(&response).expect("response JSON");
    let mut invalid_state = value.clone();
    invalid_state["response"]["value"]["state"] = serde_json::json!("active");
    invalid_state["response"]["value"]["activated_at_unix_milliseconds"] = serde_json::Value::Null;
    let mut certificate_material = value;
    certificate_material["response"]["value"]["certificate_public_material"] =
        serde_json::json!("forbidden");
    for mutation in [invalid_state, certificate_material] {
        let error = NodePrivateTransport::decode_response(
            &serde_json::to_vec(&mutation).expect("mutated response"),
        )
        .expect_err("controller response mutation");
        assert!(!error.to_string().contains("forbidden"));
    }
}
