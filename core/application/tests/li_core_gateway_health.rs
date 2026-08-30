// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_application::{
    CoreGatewayServiceHealth, CoreResidentProcess, CoreServiceSetupError,
    CoreServiceSetupObservation, CoreServiceSetupResidentHealth,
    CoreServiceSetupResidentHealthRouter,
};
use li_core_update_manager::{
    CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
};
use li_gateway_manager::{
    GatewayConfiguration, GatewayConfigurationFile, GatewayHealthError, GatewayHealthExchange,
    GatewayNativeFile, GatewayNativeFileIo, GatewayNativeIoError,
};
use serde_json::{json, Value};

// Supplies one owner-only strict Gateway configuration document.
struct ConfigurationIo {
    bytes: Vec<u8>,
}

impl GatewayNativeFileIo for ConfigurationIo {
    // Returns one exact safe in-memory configuration observation.
    fn read_no_follow(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<GatewayNativeFile, GatewayNativeIoError> {
        GatewayNativeFile::new(501, 0o600, 1, self.bytes.clone())
    }
}

// Builds one strict main or child Gateway configuration.
fn configuration(mode: &str) -> GatewayConfiguration {
    let mut document = json!({
        "schema": {"name": "li_gateway_configuration", "version": 5},
        "node_id": "11111111111111111111111111111111",
        "core_release": "1.2.3",
        "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "mode": mode,
        "health": {
            "socket_path": "/state/gateway_health.sock",
            "maximum_workers": 4,
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "accept_poll_interval_milliseconds": 10
        },
        "node_protection": {
            "socket_path": "/state/node_protection.sock",
            "read_timeout_milliseconds": 1000,
            "write_timeout_milliseconds": 1000,
            "maximum_cache_milliseconds": 2000,
            "poll_interval_milliseconds": 500
        },
        "runtime": {
            "node_socket_path": "/state/node.sock",
            "telemetry_file": "/state/gateway_telemetry_v2",
            "telemetry_cadence_milliseconds": 1000,
            "maximum_queue_milliseconds": 30000
        },
        "private_listener": {
            "address": "127.0.0.1:9444",
            "maximum_connections": 8,
            "tls": {
                "server_certificate_file": "/trust/gateway.crt",
                "server_private_key_file": "/trust/gateway.key",
                "client_ca_file": "/trust/main-ca.crt",
                "client_certificate_file": "/trust/main.crt"
            }
        }
    });
    if mode == "main" {
        document.as_object_mut().expect("object").insert(
            "public_listener".to_string(),
            json!({"address": "127.0.0.1:8080", "maximum_connections": 8}),
        );
    }
    GatewayConfiguration::load(
        &GatewayConfigurationFile::new(501, PathBuf::from("/configuration.json"))
            .expect("reference"),
        &ConfigurationIo {
            bytes: serde_json::to_vec(&document).expect("configuration"),
        },
    )
    .expect("strict configuration")
}

// Selects one exact readiness response or transport failure.
#[derive(Clone, Copy)]
enum ExchangeOutcome {
    Ready,
    NotReady,
    Failure(GatewayHealthError),
}

// Records exact deadlines and returns one protocol-shaped response.
struct ExchangeMock {
    mode: &'static str,
    outcome: ExchangeOutcome,
    calls: Mutex<Vec<Duration>>,
}

impl GatewayHealthExchange for ExchangeMock {
    // Preserves request correlation while returning the configured role and readiness.
    fn exchange(
        &self,
        _configuration: &li_gateway_manager::GatewayHealthConfiguration,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, GatewayHealthError> {
        self.calls.lock().expect("calls").push(timeout);
        if let ExchangeOutcome::Failure(error) = self.outcome {
            return Err(error);
        }
        let request: Value = serde_json::from_slice(request).expect("request");
        serde_json::to_vec(&json!({
            "schema": {"name": "li_gateway_health", "version": 1},
            "request_id": request["request_id"],
            "node_id": "11111111111111111111111111111111",
            "mode": self.mode,
            "core_release": "1.2.3",
            "core_source_identity": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "readiness": if matches!(self.outcome, ExchangeOutcome::Ready) {
                "ready"
            } else {
                "not_ready"
            }
        }))
        .map_err(|_| GatewayHealthError::InvalidResponse)
    }
}

// Returns one exact platform-independent service setup context.
fn context(role: CoreUpdateNodeRole) -> CoreUpdateServiceContext {
    CoreUpdateServiceContext::new(CoreUpdateServicePlatform::Macos, role)
}

// Proves both roles map exact protocol readiness into the setup contract.
#[test]
fn adapter_accepts_exact_main_and_child_readiness_only() {
    for (mode, role) in [
        ("main", CoreUpdateNodeRole::Main),
        ("child", CoreUpdateNodeRole::Child),
    ] {
        for (outcome, expected) in [
            (ExchangeOutcome::Ready, CoreServiceSetupObservation::Ready),
            (
                ExchangeOutcome::NotReady,
                CoreServiceSetupObservation::NotReady,
            ),
        ] {
            let health = CoreGatewayServiceHealth::new(
                configuration(mode),
                Arc::new(ExchangeMock {
                    mode,
                    outcome,
                    calls: Mutex::new(Vec::new()),
                }),
            );
            assert_eq!(
                health
                    .observe(
                        context(role),
                        CoreResidentProcess::Gateway,
                        Duration::from_secs(1),
                    )
                    .expect("observation"),
                expected
            );
        }
    }
}

// Rejects role, resident, and zero-time requests before any local exchange.
#[test]
fn adapter_rejects_context_drift_before_transport() {
    let exchange = Arc::new(ExchangeMock {
        mode: "main",
        outcome: ExchangeOutcome::Ready,
        calls: Mutex::new(Vec::new()),
    });
    let health = CoreGatewayServiceHealth::new(configuration("main"), exchange.clone());
    for (request_context, process, timeout) in [
        (
            context(CoreUpdateNodeRole::Child),
            CoreResidentProcess::Gateway,
            Duration::from_secs(1),
        ),
        (
            context(CoreUpdateNodeRole::Main),
            CoreResidentProcess::Node,
            Duration::from_secs(1),
        ),
        (
            context(CoreUpdateNodeRole::Main),
            CoreResidentProcess::Gateway,
            Duration::ZERO,
        ),
    ] {
        assert!(health.observe(request_context, process, timeout).is_err());
    }
    assert!(exchange.calls.lock().expect("calls").is_empty());
}

// Keeps transient absence not-ready while authentication and response corruption are terminal.
#[test]
fn adapter_failure_classification_is_closed_and_redacted() {
    for (failure, expected) in [
        (
            GatewayHealthError::EndpointUnavailable,
            Ok(CoreServiceSetupObservation::NotReady),
        ),
        (
            GatewayHealthError::DeadlineExceeded,
            Ok(CoreServiceSetupObservation::NotReady),
        ),
        (
            GatewayHealthError::ResidentUnavailable,
            Ok(CoreServiceSetupObservation::NotReady),
        ),
        (GatewayHealthError::AuthenticationUnavailable, Err(())),
        (GatewayHealthError::InvalidResponse, Err(())),
    ] {
        let health = CoreGatewayServiceHealth::new(
            configuration("main"),
            Arc::new(ExchangeMock {
                mode: "main",
                outcome: ExchangeOutcome::Failure(failure),
                calls: Mutex::new(Vec::new()),
            }),
        );
        let result = health.observe(
            context(CoreUpdateNodeRole::Main),
            CoreResidentProcess::Gateway,
            Duration::from_secs(1),
        );
        match expected {
            Ok(observation) => assert_eq!(result, Ok(observation)),
            Err(()) => {
                let error = result.expect_err("terminal failure");
                assert!(matches!(error, CoreServiceSetupError::Provider { .. }));
                assert!(!error.to_string().contains("11111111"));
            }
        }
    }
}

// Caps one local exchange while leaving the outer setup deadline with its caller.
#[test]
fn adapter_caps_each_exchange_to_ten_seconds() {
    let exchange = Arc::new(ExchangeMock {
        mode: "main",
        outcome: ExchangeOutcome::Ready,
        calls: Mutex::new(Vec::new()),
    });
    let health = CoreGatewayServiceHealth::new(configuration("main"), exchange.clone());
    assert_eq!(
        health.observe(
            context(CoreUpdateNodeRole::Main),
            CoreResidentProcess::Gateway,
            Duration::from_secs(90),
        ),
        Ok(CoreServiceSetupObservation::Ready)
    );
    assert_eq!(
        *exchange.calls.lock().expect("calls"),
        vec![Duration::from_secs(10)]
    );
}

// Supplies one ready non-Gateway role so the concrete Gateway can be tested through the router.
struct ReadyNode;

impl CoreServiceSetupResidentHealth for ReadyNode {
    // Reports ready only for the exact Node role selected by the router.
    fn observe(
        &self,
        _context: CoreUpdateServiceContext,
        process: CoreResidentProcess,
        _timeout: Duration,
    ) -> Result<CoreServiceSetupObservation, CoreServiceSetupError> {
        if process != CoreResidentProcess::Node {
            return Err(CoreServiceSetupError::InvalidContract {
                reason: "Node route is invalid",
            });
        }
        Ok(CoreServiceSetupObservation::Ready)
    }
}

// Proves production composition routes Gateway health without another role fallback.
#[test]
fn concrete_gateway_adapter_dispatches_through_closed_resident_router() {
    let exchange = Arc::new(ExchangeMock {
        mode: "child",
        outcome: ExchangeOutcome::Ready,
        calls: Mutex::new(Vec::new()),
    });
    let gateway: Arc<dyn CoreServiceSetupResidentHealth> = Arc::new(CoreGatewayServiceHealth::new(
        configuration("child"),
        exchange.clone(),
    ));
    let node: Arc<dyn CoreServiceSetupResidentHealth> = Arc::new(ReadyNode);
    let router = CoreServiceSetupResidentHealthRouter::new(
        CoreUpdateServicePlatform::Macos,
        vec![
            (CoreResidentProcess::Node, node),
            (CoreResidentProcess::Gateway, gateway),
        ],
    )
    .expect("router");
    assert_eq!(
        router.observe(
            context(CoreUpdateNodeRole::Child),
            CoreResidentProcess::Gateway,
            Duration::from_secs(1),
        ),
        Ok(CoreServiceSetupObservation::Ready)
    );
    assert_eq!(exchange.calls.lock().expect("calls").len(), 1);
}
