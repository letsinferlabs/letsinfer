// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreResidentProcess, CoreServiceSetupObservation, CoreServiceSetupResidentHealth,
    CoreWatchdogHealthError, CoreWatchdogHealthExchange, CoreWatchdogHealthTlsFiles,
    CoreWatchdogServiceHealth, SystemCoreWatchdogHealthExchange,
};
use li_core_interface::{InstallationId, NodeId};
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use li_watchdog_manager::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_request,
    encode_watchdog_protocol_frame, encode_watchdog_protocol_response, WatchdogConfiguration,
    WatchdogProtocolRequestKind, WatchdogProtocolResidentStatus, WatchdogProtocolResponse,
    WatchdogProtocolResponseKind,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

const NODE_ID: &str = "11111111111111111111111111111111";
const INSTALLATION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CORE_RELEASE: &str = "v0.11.0-rc.99";
const CORE_SOURCE_IDENTITY: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

// Proves an authenticated idle resident is ready and clamps one long caller bound exactly once.
#[test]
fn watchdog_health_accepts_exact_idle_identity_under_the_bounded_deadline() {
    let exchange = Arc::new(MockExchange::new(MockOutcome::ResidentStatus(
        resident_status(NODE_ID, CORE_RELEASE, CORE_SOURCE_IDENTITY, INSTALLATION_ID),
    )));
    let health = CoreWatchdogServiceHealth::new(configuration(), exchange.clone()).unwrap();
    assert_eq!(
        health
            .observe(
                linux_context(),
                CoreResidentProcess::Watchdog,
                Duration::from_secs(60),
            )
            .unwrap(),
        CoreServiceSetupObservation::Ready
    );
    let calls = exchange.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].endpoint,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_773)
    );
    assert_eq!(calls[0].timeout, Duration::from_secs(10));
    let payload = decode_watchdog_protocol_frame(&calls[0].request).unwrap();
    assert!(matches!(
        decode_watchdog_protocol_request(payload).unwrap().kind(),
        WatchdogProtocolRequestKind::GetResidentStatus
    ));
}

// Rejects either wrong immutable identity as not ready without requiring a placement.
#[test]
fn watchdog_health_rejects_wrong_node_or_core_identity() {
    for status in [
        resident_status(
            &"2".repeat(32),
            CORE_RELEASE,
            CORE_SOURCE_IDENTITY,
            INSTALLATION_ID,
        ),
        resident_status(
            NODE_ID,
            "v0.11.0-rc.100",
            CORE_SOURCE_IDENTITY,
            INSTALLATION_ID,
        ),
    ] {
        let health = CoreWatchdogServiceHealth::new(
            configuration(),
            Arc::new(MockExchange::new(MockOutcome::ResidentStatus(status))),
        )
        .unwrap();
        assert_eq!(
            health.observe_watchdog(Duration::from_secs(1)).unwrap(),
            CoreServiceSetupObservation::NotReady
        );
    }
}

// Rejects wrong installation identity and every malformed or unrelated response shape.
#[test]
fn watchdog_health_rejects_wrong_source_and_malformed_responses() {
    let cases = [
        MockOutcome::ResidentStatus(resident_status(
            NODE_ID,
            CORE_RELEASE,
            &"d".repeat(64),
            INSTALLATION_ID,
        )),
        MockOutcome::ResidentStatus(resident_status(
            NODE_ID,
            CORE_RELEASE,
            CORE_SOURCE_IDENTITY,
            &"b".repeat(64),
        )),
        MockOutcome::Frame(vec![0, 0, 0, 2, 0xff, 0xff]),
        MockOutcome::Pong,
    ];
    for outcome in cases {
        let health =
            CoreWatchdogServiceHealth::new(configuration(), Arc::new(MockExchange::new(outcome)))
                .unwrap();
        let result = health.observe_watchdog(Duration::from_secs(1));
        match result {
            Ok(CoreServiceSetupObservation::NotReady) => {}
            Err(CoreWatchdogHealthError::InvalidResponse) => {}
            other => panic!("unexpected malformed response result: {other:?}"),
        }
    }
}

// Treats a bounded Watchdog protocol error as a semantic not-ready observation.
#[test]
fn watchdog_health_treats_server_error_as_not_ready() {
    let health = CoreWatchdogServiceHealth::new(
        configuration(),
        Arc::new(MockExchange::new(MockOutcome::ServerError)),
    )
    .unwrap();
    assert_eq!(
        health.observe_watchdog(Duration::from_secs(1)).unwrap(),
        CoreServiceSetupObservation::NotReady
    );
}

// Preserves timeout, authentication, and transport classifications without diagnostic secrets.
#[test]
fn watchdog_health_redacts_transport_authentication_and_timeout_failures() {
    for failure in [
        CoreWatchdogHealthError::DeadlineExceeded,
        CoreWatchdogHealthError::AuthenticationUnavailable,
        CoreWatchdogHealthError::TransportUnavailable,
    ] {
        let health = CoreWatchdogServiceHealth::new(
            configuration(),
            Arc::new(MockExchange::new(MockOutcome::Failure(failure))),
        )
        .unwrap();
        assert_eq!(
            health.observe_watchdog(Duration::from_secs(1)),
            Err(failure)
        );
        let diagnostic = failure.to_string();
        assert!(!diagnostic.contains("secret"));
        assert!(!diagnostic.contains("127.0.0.1"));
        assert!(!diagnostic.contains("certificate"));
    }
}

// Returns not ready at an exhausted deadline without opening a transport.
#[test]
fn watchdog_health_does_not_start_after_its_deadline() {
    let exchange = Arc::new(MockExchange::new(MockOutcome::ResidentStatus(
        resident_status(NODE_ID, CORE_RELEASE, CORE_SOURCE_IDENTITY, INSTALLATION_ID),
    )));
    let health = CoreWatchdogServiceHealth::new(configuration(), exchange.clone()).unwrap();
    assert_eq!(
        health.observe_watchdog(Duration::ZERO).unwrap(),
        CoreServiceSetupObservation::NotReady
    );
    assert!(exchange.calls.lock().unwrap().is_empty());
    assert!(health
        .observe(
            CoreUpdateServiceContext::new(
                CoreUpdateServicePlatform::Macos,
                CoreUpdateNodeRole::Main,
            ),
            CoreResidentProcess::Watchdog,
            Duration::from_secs(1),
        )
        .is_err());
    assert!(health
        .observe(
            linux_context(),
            CoreResidentProcess::Node,
            Duration::from_secs(1),
        )
        .is_err());
}

// Loads one real client identity and rejects a file that is not owner-private.
#[test]
fn watchdog_health_loads_strict_mutual_tls_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let (ca, client_certificate, client_private_key) = tls_identity();
    let ca_file = temporary.path().join("server-ca.crt");
    let certificate_file = temporary.path().join("controller.crt");
    let private_key_file = temporary.path().join("controller.key");
    for (path, bytes) in [
        (ca_file.as_path(), ca.as_slice()),
        (certificate_file.as_path(), client_certificate.as_slice()),
        (private_key_file.as_path(), client_private_key.as_slice()),
    ] {
        write_private(path, bytes);
    }
    let files = CoreWatchdogHealthTlsFiles::new(
        unsafe { libc::geteuid() },
        ca_file,
        certificate_file,
        private_key_file.clone(),
    )
    .unwrap();
    SystemCoreWatchdogHealthExchange::load(&files).expect("mutual TLS identity");

    std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        SystemCoreWatchdogHealthExchange::load(&files),
        Err(CoreWatchdogHealthError::AuthenticationUnavailable)
    ));
}

// Captures one exact health exchange without interpreting the protocol request.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExchangeCall {
    endpoint: SocketAddr,
    request: Vec<u8>,
    timeout: Duration,
}

// Selects one deterministic response or closed boundary failure.
enum MockOutcome {
    ResidentStatus(WatchdogProtocolResidentStatus),
    ServerError,
    Pong,
    Frame(Vec<u8>),
    Failure(CoreWatchdogHealthError),
}

// Records one exchange and emits one request-correlated deterministic response.
struct MockExchange {
    outcome: MockOutcome,
    calls: Mutex<Vec<ExchangeCall>>,
}

impl MockExchange {
    // Creates one empty recorder with an injected outcome.
    fn new(outcome: MockOutcome) -> Self {
        Self {
            outcome,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl CoreWatchdogHealthExchange for MockExchange {
    // Correlates typed mock responses to the exact decoded request identity.
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, CoreWatchdogHealthError> {
        self.calls.lock().unwrap().push(ExchangeCall {
            endpoint,
            request: request.to_vec(),
            timeout,
        });
        if let MockOutcome::Failure(error) = self.outcome {
            return Err(error);
        }
        if let MockOutcome::Frame(frame) = &self.outcome {
            return Ok(frame.clone());
        }
        let payload = decode_watchdog_protocol_frame(request)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let request = decode_watchdog_protocol_request(payload)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let kind = match &self.outcome {
            MockOutcome::ResidentStatus(status) => {
                WatchdogProtocolResponseKind::ResidentStatus(status.clone())
            }
            MockOutcome::ServerError => WatchdogProtocolResponseKind::Error {
                code: 503,
                message: "Watchdog resident is unavailable".to_string(),
            },
            MockOutcome::Pong => WatchdogProtocolResponseKind::Pong { nonce: 1 },
            MockOutcome::Frame(_) | MockOutcome::Failure(_) => unreachable!("handled outcome"),
        };
        let response = WatchdogProtocolResponse::new(request.request_id(), kind)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        let payload = encode_watchdog_protocol_response(&response)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)?;
        encode_watchdog_protocol_frame(&payload)
            .map_err(|_| CoreWatchdogHealthError::InvalidContract)
    }
}

// Parses one complete strict Watchdog configuration fixture.
fn configuration() -> WatchdogConfiguration {
    WatchdogConfiguration::parse(
        format!(
            r#"{{
              "schema": {{"name": "li_watchdog_configuration", "version": 2}},
              "installation_id": "{INSTALLATION_ID}",
              "node_id": "{NODE_ID}",
              "core_release": "{CORE_RELEASE}",
              "core_source_identity": "{CORE_SOURCE_IDENTITY}",
              "listener": {{"address": "127.0.0.1", "port": 9773}},
              "node_protection": {{"socket_path": "/tmp/li_node_protection.sock", "read_timeout_milliseconds": 1000, "write_timeout_milliseconds": 1000}},
              "paths": {{
                "data_directory": "/var/lib/letsinfer/watchdog",
                "server_certificate_path": "/var/lib/letsinfer/watchdog.crt",
                "server_private_key_path": "/var/lib/letsinfer/watchdog.key",
                "controller_ca_path": "/var/lib/letsinfer/controller-ca.crt",
                "controller_allowlist_path": "/var/lib/letsinfer/controllers.allow",
                "controller_snapshot_path": "/var/lib/letsinfer/controllers.snapshot",
                "site_state_path": "/var/lib/letsinfer/letsinfer.state",
                "gateway_metrics_path": "/var/lib/letsinfer/gateway.metrics",
                "protection_root_path": "/var/lib/letsinfer/protection",
                "node_database_path": "/var/lib/letsinfer/core.sqlite3",
                "runtime_installation_root": "/var/lib/letsinfer/runtime-installations",
                "runtime_cache_root": "/var/lib/letsinfer/runtime-cache"
              }},
              "cadence": {{"sample_interval_milliseconds": 1000, "flush_interval_milliseconds": 10000}},
              "maximum_controllers": 8,
              "providers": {{"gpu": "nvml", "gateway_counters": "gateway_telemetry_v2"}},
              "thresholds": {{
                "warning_available_bytes": 17179869184,
                "graceful_available_bytes": 8589934592,
                "emergency_available_bytes": 4294967296,
                "swap_stop_bytes": 1073741824,
                "psi_some_microseconds": 100000,
                "psi_full_microseconds": 50000,
                "state_failures": 3,
                "containment_grace_milliseconds": 5000
              }}
            }}"#
        )
        .as_bytes(),
    )
    .unwrap()
}

// Creates one typed ready resident status fixture.
fn resident_status(
    node_id: &str,
    core_release: &str,
    core_source_identity: &str,
    installation_id: &str,
) -> WatchdogProtocolResidentStatus {
    WatchdogProtocolResidentStatus::ready(
        NodeId::parse(node_id).unwrap(),
        core_release.to_string(),
        li_core_interface::Sha256Digest::parse(core_source_identity).unwrap(),
        InstallationId::parse(installation_id).unwrap(),
    )
    .unwrap()
}

// Returns the only platform and role supported by Watchdog service health.
fn linux_context() -> CoreUpdateServiceContext {
    CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Linux, CoreUpdateNodeRole::Main)
}

// Generates one CA and exact client-auth identity entirely in memory.
fn tls_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_parameters.distinguished_name = distinguished_name("li-watchdog-health-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
    let mut client_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_parameters.distinguished_name = distinguished_name("li-watchdog-health-controller");
    let client_key = KeyPair::generate().unwrap();
    let client_certificate = client_parameters
        .signed_by(&client_key, &ca_certificate, &ca_key)
        .unwrap();
    (
        ca_certificate.pem().into_bytes(),
        client_certificate.pem().into_bytes(),
        client_key.serialize_pem().into_bytes(),
    )
}

// Creates one bounded deterministic certificate subject.
fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

// Writes one owner-private regular TLS fixture.
fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
