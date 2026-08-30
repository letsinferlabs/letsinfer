// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    EndpointAddress, EndpointScheme, LogicalModelName, NodeAddress, NodeId, PlacementGroupId,
    Sha256Digest, TokenCountContract, TokenCountProtocol,
};
use li_gateway_manager::{
    GatewayChatCompletionRequest, GatewayExecutionFailure, GatewayExecutionFailureKind,
    GatewayExecutionProvider, GatewayNativeExecutionProvider, GatewayNativeFile,
    GatewayNativeFileIo, GatewayNativeHttpFailure, GatewayNativeHttpIo, GatewayNativeHttpRequest,
    GatewayNativeHttpResponseObserver, GatewayNativeIoError, GatewayNativeResponseHead,
    GatewayNativeTarget, GatewayNativeTargetProvider, GatewayNativeTlsConfiguration,
    GatewayResponseHead, GatewayResponseWriter, GatewayRoute, GatewayRouteTarget,
    GatewayTokenCountClient, SystemGatewayNativeFileIo, LETSINFER_TOKEN_COUNT_PROTOCOL,
};
use sha2::{Digest, Sha256};

const OWNER_USER_ID: u32 = 501;
const BEARER_PATH: &str = "/private/li_engine_credential";
const CA_PATH: &str = "/private/li_engine_ca.pem";
const CLIENT_CERTIFICATE_PATH: &str = "/private/li_gateway_client.pem";
const CLIENT_PRIVATE_KEY_PATH: &str = "/private/li_gateway_client.key";
const CHILD_LEAF_SHA256: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const BEARER: &str = "li_internal_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// Resolves one deterministic target without inspecting the host.
struct TargetMock {
    target: Result<GatewayNativeTarget, GatewayNativeIoError>,
}

impl GatewayNativeTargetProvider for TargetMock {
    // Returns the exact configured target or injected resolution failure.
    fn target(&self, _route: &GatewayRoute) -> Result<GatewayNativeTarget, GatewayNativeIoError> {
        self.target.clone()
    }
}

// Supplies descriptor-derived file fixtures and records exact read boundaries.
struct FileIoMock {
    files: BTreeMap<PathBuf, GatewayNativeFile>,
    reads: Mutex<Vec<PathBuf>>,
}

impl GatewayNativeFileIo for FileIoMock {
    // Returns one immutable file fixture after applying the caller's size bound.
    fn read_no_follow(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        self.reads.lock().expect("reads").push(path.to_path_buf());
        let file = self.files.get(path).cloned().ok_or_else(|| {
            GatewayNativeIoError::terminal_before_head("mock native file is unavailable")
        })?;
        if file.bytes().len() > maximum_bytes {
            return Err(GatewayNativeIoError::terminal_before_head(
                "mock native file exceeds bound",
            ));
        }
        Ok(file)
    }
}

// Describes one deterministic response or transport failure.
enum HttpPlan {
    Response {
        head: GatewayNativeResponseHead,
        chunks: Vec<Vec<u8>>,
    },
    FailBefore,
    FailAfterHead {
        head: GatewayNativeResponseHead,
    },
    FailAfterBody {
        head: GatewayNativeResponseHead,
        body: Vec<u8>,
    },
}

// Records only the request properties needed to prove the native contract.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestObservation {
    path: String,
    host: String,
    port: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    tls_server_name: String,
    expected_server_leaf_sha256: Option<String>,
    has_client_identity: bool,
    debug: String,
}

// Replays native response events without sockets, DNS, TLS, or wall-clock access.
struct HttpIoMock {
    plans: Mutex<VecDeque<HttpPlan>>,
    requests: Mutex<Vec<RequestObservation>>,
}

impl HttpIoMock {
    // Creates one closed ordered native response script.
    fn new(plans: Vec<HttpPlan>) -> Self {
        Self {
            plans: Mutex::new(plans.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl GatewayNativeHttpIo for HttpIoMock {
    // Replays one response and preserves output failures from the real observer.
    fn send(
        &self,
        request: &GatewayNativeHttpRequest,
        observer: &mut dyn GatewayNativeHttpResponseObserver,
    ) -> Result<(), GatewayNativeHttpFailure> {
        self.requests
            .lock()
            .expect("requests")
            .push(RequestObservation {
                path: request.path().to_string(),
                host: request.host().to_string(),
                port: request.port(),
                headers: request.headers().to_vec(),
                body: request.body().to_vec(),
                tls_server_name: request.tls().server_name().to_string(),
                expected_server_leaf_sha256: request
                    .tls()
                    .expected_server_leaf_sha256()
                    .map(|digest| digest.as_str().to_string()),
                has_client_identity: request.tls().client_identity().is_some(),
                debug: format!("{request:?}"),
            });
        match self.plans.lock().expect("plans").pop_front().expect("plan") {
            HttpPlan::Response { head, chunks } => {
                observer
                    .receive_head(&head)
                    .map_err(GatewayNativeHttpFailure::Output)?;
                for chunk in chunks {
                    observer
                        .receive_body(&chunk)
                        .map_err(GatewayNativeHttpFailure::Output)?;
                }
                Ok(())
            }
            HttpPlan::FailBefore => Err(GatewayNativeHttpFailure::Native(
                GatewayNativeIoError::retryable_before_head("mock connection failed"),
            )),
            HttpPlan::FailAfterHead { head } => {
                observer
                    .receive_head(&head)
                    .map_err(GatewayNativeHttpFailure::Output)?;
                Err(GatewayNativeHttpFailure::Native(
                    GatewayNativeIoError::after_head("mock response failed"),
                ))
            }
            HttpPlan::FailAfterBody { head, body } => {
                observer
                    .receive_head(&head)
                    .map_err(GatewayNativeHttpFailure::Output)?;
                observer
                    .receive_body(&body)
                    .map_err(GatewayNativeHttpFailure::Output)?;
                Err(GatewayNativeHttpFailure::Native(
                    GatewayNativeIoError::after_head("mock stream failed"),
                ))
            }
        }
    }
}

// Records committed output without consulting a real listener or client socket.
#[derive(Default)]
struct ResponseWriterMock {
    heads: Vec<GatewayResponseHead>,
    body: Vec<u8>,
}

impl GatewayResponseWriter for ResponseWriterMock {
    // Records one caller-visible response head.
    fn write_head(&mut self, head: &GatewayResponseHead) -> Result<(), GatewayExecutionFailure> {
        self.heads.push(head.clone());
        Ok(())
    }

    // Records one caller-visible body fragment.
    fn write_body(&mut self, body: &[u8]) -> Result<(), GatewayExecutionFailure> {
        self.body.extend_from_slice(body);
        Ok(())
    }
}

// Forwards one local HTTPS JSON completion with exact headers, trust, and usage.
#[test]
fn local_engine_success_uses_fixed_https_contract() {
    let route = local_route();
    let target = local_target("engine.local");
    let files = Arc::new(file_io(false));
    let http = Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
        head: response_head(200, "application/json"),
        chunks: vec![
            b"{\"id\":\"completion\",\"usage\":{\"prompt_tokens\":10,".to_vec(),
            b"\"completion_tokens\":3,\"prompt_tokens_details\":{\"cached_tokens\":2}}}".to_vec(),
        ],
    }]));
    let provider = provider(target, files.clone(), http.clone());
    let mut output = ResponseWriterMock::default();

    let usage = provider
        .forward(&route, &chat_request(false), &mut output)
        .expect("forward");

    assert_eq!(usage.input_tokens(), 10);
    assert_eq!(usage.output_tokens(), 3);
    assert_eq!(usage.cached_tokens(), 2);
    assert_eq!(output.heads.len(), 1);
    let response_value: serde_json::Value =
        serde_json::from_slice(&output.body).expect("response JSON");
    assert_eq!(response_value["id"], "completion");
    let request = http.requests.lock().expect("requests")[0].clone();
    assert_eq!(request.path, "/v1/chat/completions");
    assert_eq!(request.host, "engine.local");
    assert_eq!(request.port, 9443);
    assert_eq!(request.tls_server_name, "engine.local");
    assert_eq!(request.expected_server_leaf_sha256, None);
    assert!(!request.has_client_identity);
    assert_eq!(header(&request, "host"), "engine.local:9443");
    assert_eq!(header(&request, "content-type"), "application/json");
    assert_eq!(header(&request, "connection"), "close");
    assert_eq!(
        header(&request, "authorization"),
        format!("Bearer {BEARER}")
    );
    assert!(!request.debug.contains(BEARER));
    assert!(!request.debug.contains("messages"));
    assert_eq!(files.reads.lock().expect("reads").len(), 2);
}

// Forwards child relay traffic only with the main's bearer and client TLS identity.
#[test]
fn child_relay_requires_mtls_and_formats_ipv6_host() {
    let route = child_route("fd00::2");
    let target = GatewayNativeTarget::child_relay(
        "fd00::2",
        9772,
        OWNER_USER_ID,
        BEARER_PATH.into(),
        CA_PATH.into(),
        Sha256Digest::parse(CHILD_LEAF_SHA256).expect("child leaf pin"),
        CLIENT_CERTIFICATE_PATH.into(),
        CLIENT_PRIVATE_KEY_PATH.into(),
        Some(token_count_contract()),
    )
    .expect("target");
    let http = Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
        head: response_head(200, "application/json"),
        chunks: vec![usage_json(10, 2, 0)],
    }]));
    let provider = provider(target, Arc::new(file_io(true)), http.clone());
    let mut output = ResponseWriterMock::default();

    provider
        .forward(&route, &chat_request(false), &mut output)
        .expect("relay");

    let request = http.requests.lock().expect("requests")[0].clone();
    assert!(request.has_client_identity);
    assert_eq!(request.tls_server_name, "fd00::2");
    assert_eq!(
        request.expected_server_leaf_sha256.as_deref(),
        Some(CHILD_LEAF_SHA256)
    );
    assert_eq!(header(&request, "host"), "[fd00::2]:9772");
}

// Proves exact child leaf pinning hashes DER bytes and rejects any other CA-valid leaf.
#[test]
fn child_server_leaf_pin_binds_exact_der_identity() {
    let enrolled_der = b"enrolled child leaf DER";
    let enrolled_sha256 =
        Sha256Digest::parse(&format!("{:x}", Sha256::digest(enrolled_der))).unwrap();
    let configuration = GatewayNativeTlsConfiguration::new(
        "child.local",
        b"pinned CA".to_vec(),
        Some(enrolled_sha256),
        None,
    )
    .unwrap();

    assert!(configuration.verify_server_leaf(enrolled_der).is_ok());
    let error = configuration
        .verify_server_leaf(b"another CA-valid child leaf DER")
        .unwrap_err();
    assert_eq!(
        error.reason(),
        "server leaf identity differs from its enrolled pin"
    );
    assert!(!format!("{configuration:?}").contains("pinned CA"));
}

// Implements the exact closed letsinfer-token-count-v1 request and response contract.
#[test]
fn exact_token_count_client_rejects_every_identity_mutation() {
    assert_eq!(LETSINFER_TOKEN_COUNT_PROTOCOL, "letsinfer-token-count-v1");
    let route = local_route();
    let valid = b"{\"model\":\"model-a\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}";
    let http = Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
        head: response_head(200, "application/json"),
        chunks: vec![
            b"{\"object\":\"token_count\",\"model\":\"model-a\",\"prompt_tokens\":17}".to_vec(),
        ],
    }]));
    let client = GatewayTokenCountClient::new(
        Arc::new(TargetMock {
            target: Ok(local_target("engine.local")),
        }),
        Arc::new(file_io(false)),
        http.clone(),
    );

    assert_eq!(client.count(&route, &model(), valid).expect("count"), 17);
    let request = http.requests.lock().expect("requests")[0].clone();
    assert_eq!(request.path, "/v1/letsinfer/token-count");
    assert_eq!(request.body, valid);

    for invalid in [
        b"{}".as_slice(),
        b"{\"model\":\"other\",\"messages\":[{}]}".as_slice(),
        b"{\"model\":\"model-a\",\"messages\":[]}".as_slice(),
        b"[]".as_slice(),
    ] {
        let client = token_client_with_no_http_calls();
        assert!(matches!(
            client.count(&route, &model(), invalid),
            Err(error) if error.kind() == GatewayExecutionFailureKind::TerminalBackend
        ));
    }

    for invalid_response in [
        b"{\"object\":\"token_count\",\"model\":\"model-a\",\"prompt_tokens\":0}".as_slice(),
        b"{\"object\":\"other\",\"model\":\"model-a\",\"prompt_tokens\":17}".as_slice(),
        b"{\"object\":\"token_count\",\"model\":\"other\",\"prompt_tokens\":17}".as_slice(),
        b"{\"object\":\"token_count\",\"model\":\"model-a\",\"prompt_tokens\":17,\"extra\":true}"
            .as_slice(),
        b"{".as_slice(),
    ] {
        let client = GatewayTokenCountClient::new(
            Arc::new(TargetMock {
                target: Ok(local_target("engine.local")),
            }),
            Arc::new(file_io(false)),
            Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
                head: response_head(200, "application/json"),
                chunks: vec![invalid_response.to_vec()],
            }])),
        );
        assert!(matches!(
            client.count(&route, &model(), valid),
            Err(error) if error.kind() == GatewayExecutionFailureKind::TerminalBackend
        ));
    }

    let endpoint = EndpointAddress::new(
        EndpointScheme::Https,
        NodeAddress::parse("engine.local").expect("host"),
        9443,
    )
    .expect("endpoint");
    let missing_contract = GatewayNativeTarget::local_engine(
        &endpoint,
        OWNER_USER_ID,
        BEARER_PATH.into(),
        CA_PATH.into(),
        None,
    )
    .expect("target without token count");
    let client = GatewayTokenCountClient::new(
        Arc::new(TargetMock {
            target: Ok(missing_contract),
        }),
        Arc::new(file_io(false)),
        Arc::new(HttpIoMock::new(Vec::new())),
    );
    assert!(matches!(
        client.count(&route, &model(), valid),
        Err(error) if error.kind() == GatewayExecutionFailureKind::TerminalBackend
    ));
}

// Reconciles arbitrarily fragmented cumulative SSE usage without double counting choices.
#[test]
fn fragmented_sse_usage_is_monotonic_and_not_double_counted() {
    let event = concat!(
        "data: {\"choices\":[{\"index\":0}],\"usage\":{\"prompt_tokens\":10,",
        "\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":1}}}\n\n",
        "data: {\"choices\":[{\"index\":0}],\"usage\":{\"prompt_tokens\":10,",
        "\"completion_tokens\":3,\"prompt_tokens_details\":{\"cached_tokens\":2}}}\n\n",
        "data: {\"choices\":[{\"index\":1}],\"usage\":{\"prompt_tokens\":10,",
        "\"completion_tokens\":1,\"prompt_tokens_details\":{\"cached_tokens\":2}}}\n\n",
        "data: [DONE]\n\n"
    )
    .as_bytes();
    let chunks = event.chunks(7).map(<[u8]>::to_vec).collect();
    let http = Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
        head: response_head(200, "text/event-stream"),
        chunks,
    }]));
    let provider = provider(
        local_target("engine.local"),
        Arc::new(file_io(false)),
        http.clone(),
    );
    let mut output = ResponseWriterMock::default();

    let usage = provider
        .forward(&local_route(), &chat_request(true), &mut output)
        .expect("stream");

    assert_eq!(usage.input_tokens(), 10);
    assert_eq!(usage.output_tokens(), 4);
    assert_eq!(usage.cached_tokens(), 2);
    assert_eq!(output.body, event);
    let body: serde_json::Value =
        serde_json::from_slice(&http.requests.lock().expect("requests")[0].body)
            .expect("instrumented body");
    assert_eq!(body["stream_options"]["include_usage"], true);
}

// Classifies connection and 5xx failures as retryable only before caller-visible output.
#[test]
fn pre_head_network_and_5xx_failures_are_retryable_without_output() {
    for plan in [
        HttpPlan::FailBefore,
        HttpPlan::Response {
            head: response_head(503, "application/json"),
            chunks: vec![b"unavailable".to_vec()],
        },
    ] {
        let provider = provider(
            local_target("engine.local"),
            Arc::new(file_io(false)),
            Arc::new(HttpIoMock::new(vec![plan])),
        );
        let mut output = ResponseWriterMock::default();
        let error = provider
            .forward(&local_route(), &chat_request(false), &mut output)
            .expect_err("retryable");
        assert_eq!(error.kind(), GatewayExecutionFailureKind::RetryableBackend);
        assert!(output.heads.is_empty());
        assert!(output.body.is_empty());
    }
}

// Never reclassifies a transport failure as retryable after head or body commitment.
#[test]
fn post_head_and_post_body_failures_are_terminal_non_replay() {
    for (plan, expected_body) in [
        (
            HttpPlan::FailAfterHead {
                head: response_head(200, "application/json"),
            },
            Vec::new(),
        ),
        (
            HttpPlan::FailAfterBody {
                head: response_head(200, "application/json"),
                body: b"{".to_vec(),
            },
            b"{".to_vec(),
        ),
    ] {
        let provider = provider(
            local_target("engine.local"),
            Arc::new(file_io(false)),
            Arc::new(HttpIoMock::new(vec![plan])),
        );
        let mut output = ResponseWriterMock::default();
        let error = provider
            .forward(&local_route(), &chat_request(false), &mut output)
            .expect_err("terminal");
        assert_eq!(error.kind(), GatewayExecutionFailureKind::TerminalBackend);
        assert_eq!(output.heads.len(), 1);
        assert_eq!(output.body, expected_body);
    }
}

// Rejects plaintext, route mismatch, unsafe bearer, CA, key, and hard-link metadata before I/O.
#[test]
fn tls_hostname_and_private_file_safety_matrix_fails_closed() {
    let http_endpoint = EndpointAddress::new(
        EndpointScheme::Http,
        NodeAddress::parse("engine.local").expect("host"),
        9443,
    )
    .expect("endpoint");
    assert!(GatewayNativeTarget::local_engine(
        &http_endpoint,
        OWNER_USER_ID,
        BEARER_PATH.into(),
        CA_PATH.into(),
        None,
    )
    .is_err());

    for (path, file) in [
        (
            BEARER_PATH,
            GatewayNativeFile::new(0, 0o600, 1, BEARER.as_bytes().to_vec()).expect("file"),
        ),
        (
            BEARER_PATH,
            GatewayNativeFile::new(OWNER_USER_ID, 0o640, 1, BEARER.as_bytes().to_vec())
                .expect("file"),
        ),
        (
            BEARER_PATH,
            GatewayNativeFile::new(OWNER_USER_ID, 0o600, 2, BEARER.as_bytes().to_vec())
                .expect("file"),
        ),
        (
            CA_PATH,
            GatewayNativeFile::new(OWNER_USER_ID, 0o644, 1, b"CA".to_vec()).expect("file"),
        ),
    ] {
        let mut files = file_map(false);
        files.insert(path.into(), file);
        let provider = provider(
            local_target("engine.local"),
            Arc::new(FileIoMock {
                files,
                reads: Mutex::new(Vec::new()),
            }),
            Arc::new(HttpIoMock::new(Vec::new())),
        );
        let mut output = ResponseWriterMock::default();
        assert!(matches!(
            provider.forward(&local_route(), &chat_request(false), &mut output),
            Err(error) if error.kind() == GatewayExecutionFailureKind::TerminalBackend
        ));
    }

    let provider = provider(
        local_target("other.local"),
        Arc::new(file_io(false)),
        Arc::new(HttpIoMock::new(Vec::new())),
    );
    let mut output = ResponseWriterMock::default();
    assert!(provider
        .forward(&local_route(), &chat_request(false), &mut output)
        .is_err());

    let root = std::env::temp_dir().join(format!(
        "li_gateway_native_no_follow_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("test directory");
    let target = root.join("credential");
    let link = root.join("credential_link");
    fs::write(&target, BEARER).expect("credential");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("mode");
    symlink(&target, &link).expect("symlink");
    assert!(SystemGatewayNativeFileIo
        .read_no_follow(&link, 512)
        .is_err());
    fs::remove_dir_all(&root).expect("cleanup");
}

// Rejects malformed usage and bounded-parser overflow only after the committed response head.
#[test]
fn malformed_and_oversized_responses_fail_without_replay() {
    for chunks in [
        vec![b"{\"usage\":false}".to_vec()],
        vec![vec![b'x'; 128 * 1024], vec![b'y']],
    ] {
        let provider = provider(
            local_target("engine.local"),
            Arc::new(file_io(false)),
            Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
                head: response_head(200, "application/json"),
                chunks,
            }])),
        );
        let mut output = ResponseWriterMock::default();
        let error = provider
            .forward(&local_route(), &chat_request(false), &mut output)
            .expect_err("malformed response");
        assert_eq!(error.kind(), GatewayExecutionFailureKind::TerminalBackend);
        assert_eq!(output.heads.len(), 1);
    }
    assert!(GatewayNativeResponseHead::new(200, vec![("bad header".into(), "x".into())]).is_err());
    assert!(GatewayNativeResponseHead::new(
        200,
        (0..65)
            .map(|index| (format!("x-{index}"), "value".to_string()))
            .collect(),
    )
    .is_err());
}

// Preserves client cleanup and secret redaction when caller output fails.
#[test]
fn output_failure_stops_native_flow_and_releases_loaded_material() {
    struct FailingWriter;
    impl GatewayResponseWriter for FailingWriter {
        // Fails before making the response head visible to the caller.
        fn write_head(
            &mut self,
            _head: &GatewayResponseHead,
        ) -> Result<(), GatewayExecutionFailure> {
            Err(GatewayExecutionFailure::client("mock client disconnected"))
        }

        // Rejects unreachable body output after head failure.
        fn write_body(&mut self, _body: &[u8]) -> Result<(), GatewayExecutionFailure> {
            panic!("body must not be written")
        }
    }

    let files = Arc::new(file_io(false));
    let http = Arc::new(HttpIoMock::new(vec![HttpPlan::Response {
        head: response_head(200, "application/json"),
        chunks: vec![usage_json(10, 1, 0)],
    }]));
    let provider = provider(local_target("engine.local"), files.clone(), http.clone());
    let error = provider
        .forward(&local_route(), &chat_request(false), &mut FailingWriter)
        .expect_err("client failure");

    assert_eq!(error.kind(), GatewayExecutionFailureKind::Client);
    assert_eq!(files.reads.lock().expect("reads").len(), 2);
    assert_eq!(http.requests.lock().expect("requests").len(), 1);
    assert!(http.plans.lock().expect("plans").is_empty());
    assert!(!http.requests.lock().expect("requests")[0]
        .debug
        .contains(BEARER));
}

// Creates one concrete provider from deterministic target, file, and HTTP boundaries.
fn provider(
    target: GatewayNativeTarget,
    files: Arc<FileIoMock>,
    http: Arc<HttpIoMock>,
) -> GatewayNativeExecutionProvider {
    GatewayNativeExecutionProvider::new(Arc::new(TargetMock { target: Ok(target) }), files, http)
}

// Creates one token client whose invalid requests must stop before native HTTP.
fn token_client_with_no_http_calls() -> GatewayTokenCountClient {
    GatewayTokenCountClient::new(
        Arc::new(TargetMock {
            target: Ok(local_target("engine.local")),
        }),
        Arc::new(file_io(false)),
        Arc::new(HttpIoMock::new(Vec::new())),
    )
}

// Creates one deterministic local HTTPS route.
fn local_route() -> GatewayRoute {
    let endpoint = EndpointAddress::new(
        EndpointScheme::Https,
        NodeAddress::parse("engine.local").expect("host"),
        9443,
    )
    .expect("endpoint");
    route(GatewayRouteTarget::LocalEngine { endpoint })
}

// Creates one deterministic authenticated child route.
fn child_route(address: &str) -> GatewayRoute {
    route(GatewayRouteTarget::ChildRelay {
        address: NodeAddress::parse(address).expect("address"),
    })
}

// Creates one route with fixed capacity and identity fields.
fn route(target: GatewayRouteTarget) -> GatewayRoute {
    GatewayRoute::new(
        PlacementGroupId::parse(&"1".repeat(32)).expect("group"),
        NodeId::parse(&"2".repeat(32)).expect("node"),
        model(),
        target,
        NonZeroU32::new(1).expect("capacity"),
        NonZeroU64::new(4096).expect("context"),
        true,
        false,
        None,
        Vec::new(),
    )
    .expect("route")
}

// Creates one local native target using fixture credential references.
fn local_target(host: &str) -> GatewayNativeTarget {
    let endpoint = EndpointAddress::new(
        EndpointScheme::Https,
        NodeAddress::parse(host).expect("host"),
        9443,
    )
    .expect("endpoint");
    GatewayNativeTarget::local_engine(
        &endpoint,
        OWNER_USER_ID,
        BEARER_PATH.into(),
        CA_PATH.into(),
        Some(token_count_contract()),
    )
    .expect("target")
}

// Creates the endpoint-declared exact token-count contract used by fixtures.
fn token_count_contract() -> TokenCountContract {
    TokenCountContract::new("/v1/letsinfer/token-count", TokenCountProtocol::LetsInferV1)
        .expect("token-count contract")
}

// Creates one exact admitted chat-completions request.
fn chat_request(streaming: bool) -> GatewayChatCompletionRequest {
    let request = li_gateway_manager::GatewayRequest::new(
        Sha256Digest::parse(&"a".repeat(64)).expect("request id"),
        model(),
        NonZeroU64::new(10).expect("input"),
        NonZeroU64::new(32).expect("output"),
        None,
        0,
    )
    .expect("request");
    let body = format!(
        "{{\"model\":\"model-a\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}],\"stream\":{streaming}}}"
    )
    .into_bytes();
    GatewayChatCompletionRequest::new(request, body).expect("chat request")
}

// Creates the fixture logical-model identity.
fn model() -> LogicalModelName {
    LogicalModelName::parse("model-a").expect("model")
}

// Creates one safe native response head with headers that exercise filtering.
fn response_head(status_code: u16, content_type: &str) -> GatewayNativeResponseHead {
    GatewayNativeResponseHead::new(
        status_code,
        vec![
            ("content-type".to_string(), content_type.to_string()),
            ("server".to_string(), "private-engine".to_string()),
            ("connection".to_string(), "close".to_string()),
        ],
    )
    .expect("head")
}

// Creates one exact bounded JSON usage response.
fn usage_json(input: u64, output: u64, cached: u64) -> Vec<u8> {
    format!(
        "{{\"usage\":{{\"prompt_tokens\":{input},\"completion_tokens\":{output},\"prompt_tokens_details\":{{\"cached_tokens\":{cached}}}}}}}"
    )
    .into_bytes()
}

// Creates the full deterministic native file set.
fn file_io(client_identity: bool) -> FileIoMock {
    FileIoMock {
        files: file_map(client_identity),
        reads: Mutex::new(Vec::new()),
    }
}

// Creates private user-owned file observations for each fixture path.
fn file_map(client_identity: bool) -> BTreeMap<PathBuf, GatewayNativeFile> {
    let mut files = BTreeMap::from([
        (
            BEARER_PATH.into(),
            GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, format!("{BEARER}\n").into_bytes())
                .expect("bearer"),
        ),
        (
            CA_PATH.into(),
            GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, b"PINNED CA".to_vec()).expect("CA"),
        ),
    ]);
    if client_identity {
        files.insert(
            CLIENT_CERTIFICATE_PATH.into(),
            GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, b"CLIENT CERT".to_vec())
                .expect("certificate"),
        );
        files.insert(
            CLIENT_PRIVATE_KEY_PATH.into(),
            GatewayNativeFile::new(OWNER_USER_ID, 0o600, 1, b"CLIENT KEY".to_vec())
                .expect("private key"),
        );
    }
    files
}

// Returns one observed fixed header value by its lowercase name.
fn header(request: &RequestObservation, name: &str) -> String {
    request
        .headers
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.clone())
        .expect("header")
}
