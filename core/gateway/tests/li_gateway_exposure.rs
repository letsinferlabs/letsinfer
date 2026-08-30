// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::Sha256Digest;
use li_gateway_manager::{
    GatewayExposureCommand, GatewayExposureCommandOutput, GatewayExposureCommandRunner,
    GatewayExposureCoordinator, GatewayExposureError, GatewayExposureProvider,
    GatewayExposureReadinessProvider, GatewayExposureStore, TailscaleGatewayExposureProvider,
    LETSINFER_PUBLIC_INFERENCE_TARGET,
};
use serde_json::{json, Value};

// Stores one deterministic Tailscale process state and injected failure schedule.
struct TailscaleMock {
    status: Mutex<Value>,
    dns_name: Mutex<String>,
    commands: Mutex<Vec<Vec<String>>>,
    failures: Mutex<BTreeMap<Vec<String>, usize>>,
    ignore_reset: Mutex<bool>,
}

impl TailscaleMock {
    // Creates one empty provider namespace with a stable public DNS identity.
    fn new() -> Self {
        Self {
            status: Mutex::new(json!({})),
            dns_name: Mutex::new("inference.example.ts.net.".to_string()),
            commands: Mutex::new(Vec::new()),
            failures: Mutex::new(BTreeMap::new()),
            ignore_reset: Mutex::new(false),
        }
    }

    // Replaces the complete provider status returned by subsequent observations.
    fn set_status(&self, status: Value) {
        *self.status.lock().expect("status") = status;
    }

    // Replaces the public DNS value returned by the provider.
    fn set_dns_name(&self, dns_name: &str) {
        *self.dns_name.lock().expect("DNS name") = dns_name.to_string();
    }

    // Schedules one exact command to fail the requested number of times.
    fn fail(&self, arguments: &[&str], count: usize) {
        self.failures.lock().expect("failures").insert(
            arguments.iter().map(|value| value.to_string()).collect(),
            count,
        );
    }

    // Returns the complete exact argv history without executable paths.
    fn commands(&self) -> Vec<Vec<String>> {
        self.commands.lock().expect("commands").clone()
    }

    // Returns one successful bounded JSON command result.
    fn success(value: Value) -> Result<GatewayExposureCommandOutput, GatewayExposureError> {
        GatewayExposureCommandOutput::new(
            0,
            serde_json::to_vec(&value).expect("JSON"),
            Vec::new(),
            false,
        )
    }
}

impl GatewayExposureCommandRunner for TailscaleMock {
    // Applies one exact mocked Tailscale command without filesystem or network access.
    fn run(
        &self,
        command: &GatewayExposureCommand,
    ) -> Result<GatewayExposureCommandOutput, GatewayExposureError> {
        assert_eq!(command.executable(), PathBuf::from("/usr/bin/tailscale"));
        assert_eq!(command.maximum_output_bytes(), 1024 * 1024);
        assert_eq!(command.timeout().as_secs(), 20);
        let arguments: Vec<String> = command
            .arguments()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        self.commands
            .lock()
            .expect("commands")
            .push(arguments.clone());
        if let Some(remaining) = self.failures.lock().expect("failures").get_mut(&arguments) {
            if *remaining > 0 {
                *remaining -= 1;
                return GatewayExposureCommandOutput::new(
                    1,
                    Vec::new(),
                    b"failure".to_vec(),
                    false,
                );
            }
        }
        match arguments.as_slice() {
            [funnel, status, json] if [funnel, status, json] == ["funnel", "status", "--json"] => {
                Self::success(self.status.lock().expect("status").clone())
            }
            [status, json] if [status, json] == ["status", "--json"] => Self::success(json!({
                "Self": {"DNSName": self.dns_name.lock().expect("DNS name").clone()}
            })),
            [funnel, background, yes, https, port, target]
                if [funnel, background, yes, https, port, target]
                    == [
                        "funnel",
                        "--bg",
                        "--yes",
                        "--https",
                        "443",
                        LETSINFER_PUBLIC_INFERENCE_TARGET,
                    ] =>
            {
                self.set_status(owned_status());
                Self::success(Value::Null)
            }
            [funnel, reset] if [funnel, reset] == ["funnel", "reset"] => {
                if !*self.ignore_reset.lock().expect("ignore reset") {
                    self.set_status(json!({}));
                }
                Self::success(Value::Null)
            }
            _ => GatewayExposureCommandOutput::new(1, Vec::new(), b"unexpected".to_vec(), false),
        }
    }
}

// Returns the exact inference-only Funnel status accepted by production parsing.
fn owned_status() -> Value {
    json!({
        "TCP": {"443": {"HTTPS": true}},
        "Web": {
            "inference.example.ts.net:443": {
                "Handlers": {"/": {"Proxy": LETSINFER_PUBLIC_INFERENCE_TARGET}}
            }
        },
        "AllowFunnel": {"inference.example.ts.net:443": true}
    })
}

// Creates one production provider around a deterministic native-command mock.
fn provider(mock: Arc<TailscaleMock>) -> TailscaleGatewayExposureProvider {
    TailscaleGatewayExposureProvider::new(PathBuf::from("/usr/bin/tailscale"), mock)
        .expect("provider")
}

// Enables, verifies, and disables one exact hash-bound inference exposure.
#[test]
fn exposure_lifecycle_is_exact_replay_safe_and_hash_bound() {
    let mock = Arc::new(TailscaleMock::new());
    let provider = provider(mock.clone());
    let exposure = provider.enable().expect("enable");
    assert_eq!(exposure.provider(), "tailscale-funnel");
    assert_eq!(exposure.public_url(), "https://inference.example.ts.net");
    assert_eq!(
        exposure.configuration_sha256().as_str(),
        "cfaf749ac568fff7bdce9b8d4ef2d3348a8227e33d38366950b1ee3a29fe4ccd"
    );
    assert_eq!(
        provider
            .verify(exposure.configuration_sha256())
            .expect("verify"),
        exposure
    );
    provider
        .disable(exposure.configuration_sha256())
        .expect("disable");
    assert_eq!(*mock.status.lock().expect("status"), json!({}));
    assert_eq!(
        mock.commands(),
        [
            vec!["funnel", "status", "--json"],
            vec![
                "funnel",
                "--bg",
                "--yes",
                "--https",
                "443",
                LETSINFER_PUBLIC_INFERENCE_TARGET,
            ],
            vec!["funnel", "status", "--json"],
            vec!["status", "--json"],
            vec!["funnel", "status", "--json"],
            vec!["status", "--json"],
            vec!["funnel", "status", "--json"],
            vec!["status", "--json"],
            vec!["funnel", "reset"],
            vec!["funnel", "status", "--json"],
        ]
        .map(|arguments| arguments
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>())
    );
}

// Rejects untrusted executable locations before any provider command can run.
#[test]
fn provider_configuration_accepts_only_explicit_tailscale_locations() {
    for path in [
        "/tmp/tailscale",
        "/usr/bin/../bin/tailscale",
        "/usr/bin/tailscale-other",
        "usr/bin/tailscale",
    ] {
        assert!(matches!(
            TailscaleGatewayExposureProvider::new(
                PathBuf::from(path),
                Arc::new(TailscaleMock::new())
            ),
            Err(GatewayExposureError::InvalidConfiguration)
        ));
    }
}

// Refuses every foreign or broadened Funnel state without issuing a reset.
#[test]
fn exposure_ownership_mutation_matrix_fails_before_reset() {
    let mutations = [
        json!({"Web": {"foreign": {"Proxy": "http://127.0.0.1:9000"}}}),
        json!({
            "TCP": {"443": {"HTTPS": true}, "22": {"TCPForward": "127.0.0.1:22"}},
            "Web": {"inference.example.ts.net:443": {"Handlers": {"/": {"Proxy": LETSINFER_PUBLIC_INFERENCE_TARGET}}}},
            "AllowFunnel": {"inference.example.ts.net:443": true}
        }),
        json!({
            "TCP": {"443": {"HTTPS": true}},
            "Web": {"inference.example.ts.net:443": {"Handlers": {
                "/": {"Proxy": LETSINFER_PUBLIC_INFERENCE_TARGET},
                "/private": {"Proxy": "http://127.0.0.1:9771"}
            }}},
            "AllowFunnel": {"inference.example.ts.net:443": true}
        }),
        json!({
            "TCP": {"443": {"HTTPS": true}},
            "Web": {"inference.example.ts.net:443": {"Handlers": {"/": {"Proxy": LETSINFER_PUBLIC_INFERENCE_TARGET}}}},
            "AllowFunnel": {"different.example.ts.net:443": true}
        }),
        json!({
            "TCP": {"443": {"HTTPS": true}},
            "Web": {"inference.example.ts.net:443": {"Handlers": {"/": {"Proxy": LETSINFER_PUBLIC_INFERENCE_TARGET}}}},
            "AllowFunnel": {"inference.example.ts.net:443": true},
            "Foreground": {}
        }),
    ];
    for mutation in mutations {
        let mock = Arc::new(TailscaleMock::new());
        mock.set_status(mutation);
        let provider = provider(mock.clone());
        assert_eq!(
            provider.verify(&Sha256Digest::parse(&"0".repeat(64)).expect("digest")),
            Err(GatewayExposureError::ProviderStateUnsafe)
        );
        assert!(!mock
            .commands()
            .iter()
            .any(|arguments| arguments == &["funnel", "reset"]));
    }
}

// Rejects identity drift before reset and reports a provider that remains configured.
#[test]
fn disable_requires_exact_identity_and_observes_reset_completion() {
    let mock = Arc::new(TailscaleMock::new());
    mock.set_status(owned_status());
    let provider = provider(mock.clone());
    assert_eq!(
        provider.disable(&Sha256Digest::parse(&"0".repeat(64)).expect("digest")),
        Err(GatewayExposureError::ProviderIdentityChanged)
    );
    assert!(!mock
        .commands()
        .iter()
        .any(|arguments| arguments == &["funnel", "reset"]));
    let exposure = provider
        .verify(
            &Sha256Digest::parse(
                "cfaf749ac568fff7bdce9b8d4ef2d3348a8227e33d38366950b1ee3a29fe4ccd",
            )
            .expect("digest"),
        )
        .expect("verify");
    *mock.ignore_reset.lock().expect("ignore reset") = true;
    assert_eq!(
        provider.disable(exposure.configuration_sha256()),
        Err(GatewayExposureError::ProviderStateUnsafe)
    );
}

// Rolls back unsafe post-activation state and surfaces reset failure distinctly.
#[test]
fn enable_rolls_back_every_post_activation_validation_failure() {
    for (dns_name, reset_failure, expected) in [
        (
            "invalid name.",
            false,
            GatewayExposureError::ProviderStateUnsafe,
        ),
        (
            "invalid name.",
            true,
            GatewayExposureError::RollbackIncomplete,
        ),
    ] {
        let mock = Arc::new(TailscaleMock::new());
        mock.set_dns_name(dns_name);
        if reset_failure {
            mock.fail(&["funnel", "reset"], 1);
        }
        let provider = provider(mock.clone());
        assert_eq!(provider.enable(), Err(expected));
        assert!(mock
            .commands()
            .iter()
            .any(|arguments| arguments == &["funnel", "reset"]));
        if !reset_failure {
            assert_eq!(*mock.status.lock().expect("status"), json!({}));
        }
    }
}

// Keeps initial foreign state and process failure outside partial activation cleanup.
#[test]
fn enable_failure_boundaries_do_not_reset_unowned_state() {
    let foreign = Arc::new(TailscaleMock::new());
    foreign.set_status(json!({"foreign": true}));
    assert_eq!(
        provider(foreign.clone()).enable(),
        Err(GatewayExposureError::ProviderStateUnsafe)
    );
    assert_eq!(foreign.commands(), [vec!["funnel", "status", "--json"]]);

    let failed = Arc::new(TailscaleMock::new());
    failed.fail(
        &[
            "funnel",
            "--bg",
            "--yes",
            "--https",
            "443",
            LETSINFER_PUBLIC_INFERENCE_TARGET,
        ],
        1,
    );
    assert_eq!(
        provider(failed.clone()).enable(),
        Err(GatewayExposureError::ProviderUnavailable)
    );
    assert!(!failed
        .commands()
        .iter()
        .any(|arguments| arguments == &["funnel", "reset"]));
}

// Rejects aggregate output above the production ceiling before parsing.
#[test]
fn command_output_contract_enforces_the_aggregate_bound() {
    assert_eq!(
        GatewayExposureCommandOutput::new(0, vec![b'a'; 1024 * 1024], vec![b'b'], false,),
        Err(GatewayExposureError::ProviderUnavailable)
    );
    let timed_out =
        GatewayExposureCommandOutput::new(0, Vec::new(), Vec::new(), true).expect("bounded output");
    assert!(!timed_out.is_success());
    assert!(timed_out.timed_out());
    assert!(timed_out.standard_error().is_empty());
}

// Stores one deterministic exposure state and precise injected persistence failures.
struct ExposureStoreMock {
    exposure: Mutex<Option<li_gateway_manager::GatewayExposure>>,
    read_failures: Mutex<usize>,
    replace_failures: Mutex<usize>,
    replacements: Mutex<
        Vec<(
            Option<li_gateway_manager::GatewayExposure>,
            Option<li_gateway_manager::GatewayExposure>,
        )>,
    >,
}

impl ExposureStoreMock {
    // Creates one store with the exact initial durable exposure state.
    fn new(exposure: Option<li_gateway_manager::GatewayExposure>) -> Self {
        Self {
            exposure: Mutex::new(exposure),
            read_failures: Mutex::new(0),
            replace_failures: Mutex::new(0),
            replacements: Mutex::new(Vec::new()),
        }
    }

    // Injects one exact number of subsequent state-read failures.
    fn fail_reads(&self, count: usize) {
        *self.read_failures.lock().expect("read failures") = count;
    }

    // Injects one exact number of subsequent state-commit failures.
    fn fail_replacements(&self, count: usize) {
        *self.replace_failures.lock().expect("replace failures") = count;
    }
}

impl GatewayExposureStore for ExposureStoreMock {
    // Returns the deterministic state unless the next read failure is scheduled.
    fn exposure(
        &self,
    ) -> Result<Option<li_gateway_manager::GatewayExposure>, GatewayExposureError> {
        let mut failures = self.read_failures.lock().expect("read failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(GatewayExposureError::StateUnavailable);
        }
        Ok(self.exposure.lock().expect("exposure").clone())
    }

    // Records and applies one complete replacement unless its commit failure is scheduled.
    fn replace(
        &self,
        expected: Option<&li_gateway_manager::GatewayExposure>,
        replacement: Option<&li_gateway_manager::GatewayExposure>,
    ) -> Result<(), GatewayExposureError> {
        let expected = expected.cloned();
        let replacement = replacement.cloned();
        self.replacements
            .lock()
            .expect("replacements")
            .push((expected.clone(), replacement.clone()));
        let mut failures = self.replace_failures.lock().expect("replace failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(GatewayExposureError::StateUnavailable);
        }
        if *self.exposure.lock().expect("exposure") != expected {
            return Err(GatewayExposureError::StateUnavailable);
        }
        *self.exposure.lock().expect("exposure") = replacement;
        Ok(())
    }
}

// Controls the main Gateway readiness boundary without native services.
struct ExposureReadinessMock {
    ready: Mutex<bool>,
    calls: AtomicUsize,
}

impl ExposureReadinessMock {
    // Creates one deterministic readiness result.
    fn new(ready: bool) -> Self {
        Self {
            ready: Mutex::new(ready),
            calls: AtomicUsize::new(0),
        }
    }
}

impl GatewayExposureReadinessProvider for ExposureReadinessMock {
    // Requires the configured deterministic main Gateway state.
    fn require_ready(&self) -> Result<(), GatewayExposureError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if *self.ready.lock().expect("ready") {
            Ok(())
        } else {
            Err(GatewayExposureError::GatewayUnavailable)
        }
    }
}

// Emulates one external exposure provider with exact calls and injected failures.
struct ExposureProviderMock {
    enabled_value: Mutex<li_gateway_manager::GatewayExposure>,
    live: Mutex<Option<li_gateway_manager::GatewayExposure>>,
    enable_failures: Mutex<usize>,
    verify_failures: Mutex<usize>,
    disable_failures: Mutex<usize>,
    calls: Mutex<Vec<String>>,
}

impl ExposureProviderMock {
    // Creates one empty provider that enables the supplied stable identity.
    fn new(enabled_value: li_gateway_manager::GatewayExposure) -> Self {
        Self {
            enabled_value: Mutex::new(enabled_value),
            live: Mutex::new(None),
            enable_failures: Mutex::new(0),
            verify_failures: Mutex::new(0),
            disable_failures: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
        }
    }

    // Schedules one exact number of subsequent enable failures.
    fn fail_enables(&self, count: usize) {
        *self.enable_failures.lock().expect("enable failures") = count;
    }

    // Schedules one exact number of subsequent verification failures.
    fn fail_verifications(&self, count: usize) {
        *self.verify_failures.lock().expect("verify failures") = count;
    }

    // Schedules one exact number of subsequent disable failures.
    fn fail_disables(&self, count: usize) {
        *self.disable_failures.lock().expect("disable failures") = count;
    }
}

impl GatewayExposureProvider for ExposureProviderMock {
    // Enables the configured identity only when no failure is scheduled.
    fn enable(&self) -> Result<li_gateway_manager::GatewayExposure, GatewayExposureError> {
        self.calls.lock().expect("calls").push("enable".to_string());
        let mut failures = self.enable_failures.lock().expect("enable failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        let exposure = self.enabled_value.lock().expect("enabled value").clone();
        *self.live.lock().expect("live") = Some(exposure.clone());
        Ok(exposure)
    }

    // Verifies the expected digest and returns the complete deterministic live identity.
    fn verify(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<li_gateway_manager::GatewayExposure, GatewayExposureError> {
        self.calls
            .lock()
            .expect("calls")
            .push(format!("verify:{}", expected_configuration_sha256.as_str()));
        let mut failures = self.verify_failures.lock().expect("verify failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        let exposure = self
            .live
            .lock()
            .expect("live")
            .clone()
            .ok_or(GatewayExposureError::ProviderStateUnsafe)?;
        if exposure.configuration_sha256() != expected_configuration_sha256 {
            return Err(GatewayExposureError::ProviderIdentityChanged);
        }
        Ok(exposure)
    }

    // Disables only the expected exact live identity unless a failure is scheduled.
    fn disable(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<(), GatewayExposureError> {
        self.calls.lock().expect("calls").push(format!(
            "disable:{}",
            expected_configuration_sha256.as_str()
        ));
        let mut failures = self.disable_failures.lock().expect("disable failures");
        if *failures > 0 {
            *failures -= 1;
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        let mut live = self.live.lock().expect("live");
        let exposure = live
            .as_ref()
            .ok_or(GatewayExposureError::ProviderStateUnsafe)?;
        if exposure.configuration_sha256() != expected_configuration_sha256 {
            return Err(GatewayExposureError::ProviderIdentityChanged);
        }
        *live = None;
        Ok(())
    }
}

// Creates one valid exposure identity for lifecycle-policy tests.
fn exposure(public_url: &str, digest_byte: char) -> li_gateway_manager::GatewayExposure {
    li_gateway_manager::GatewayExposure::new(
        public_url.to_string(),
        Sha256Digest::parse(&digest_byte.to_string().repeat(64)).expect("digest"),
    )
    .expect("exposure")
}

// Creates one manager and retains its deterministic capability mocks for assertions.
fn manager_environment(
    initial: Option<li_gateway_manager::GatewayExposure>,
) -> (
    GatewayExposureCoordinator,
    Arc<ExposureStoreMock>,
    Arc<ExposureReadinessMock>,
    Arc<ExposureProviderMock>,
) {
    let store = Arc::new(ExposureStoreMock::new(initial));
    let readiness = Arc::new(ExposureReadinessMock::new(true));
    let provider = Arc::new(ExposureProviderMock::new(exposure(
        "https://inference.example.ts.net",
        'a',
    )));
    (
        GatewayExposureCoordinator::new(store.clone(), readiness.clone(), provider.clone()),
        store,
        readiness,
        provider,
    )
}

// Rejects malformed public origins before they can enter durable manager state.
#[test]
fn exposure_identity_requires_one_canonical_https_origin() {
    for value in [
        "http://inference.example.ts.net",
        "https://inference.example.ts.net/",
        "https://inference.example.ts.net.",
        "https://invalid name",
        "https://",
    ] {
        assert_eq!(
            li_gateway_manager::GatewayExposure::new(
                value.to_string(),
                Sha256Digest::parse(&"a".repeat(64)).expect("digest")
            ),
            Err(GatewayExposureError::InvalidConfiguration)
        );
    }
}

// Verifies disabled and enabled state without changing either durable or provider state.
#[test]
fn manager_status_is_read_only_and_marks_provider_drift_unverified() {
    let (manager, store, _, provider) = manager_environment(None);
    let disabled = manager.status().expect("disabled status");
    assert_eq!(disabled.exposure(), None);
    assert!(disabled.provider_verified());
    assert!(provider.calls.lock().expect("calls").is_empty());

    let expected = exposure("https://inference.example.ts.net", 'a');
    *store.exposure.lock().expect("exposure") = Some(expected.clone());
    *provider.live.lock().expect("live") = Some(expected.clone());
    let enabled = manager.status().expect("enabled status");
    assert_eq!(enabled.exposure(), Some(&expected));
    assert!(enabled.provider_verified());
    *provider.live.lock().expect("live") = Some(exposure("https://different.example.ts.net", 'a'));
    assert!(!manager.status().expect("drift status").provider_verified());
    provider.fail_verifications(1);
    assert!(!manager
        .status()
        .expect("failure status")
        .provider_verified());
    assert!(store.replacements.lock().expect("replacements").is_empty());
}

// Stops before provider mutation when readiness or durable preconditions fail.
#[test]
fn manager_enable_preconditions_are_fail_closed_and_mutation_free() {
    let (manager, store, readiness, provider) = manager_environment(None);
    *readiness.ready.lock().expect("ready") = false;
    assert_eq!(
        manager.enable(),
        Err(GatewayExposureError::GatewayUnavailable)
    );
    assert!(provider.calls.lock().expect("calls").is_empty());
    *readiness.ready.lock().expect("ready") = true;
    store.fail_reads(1);
    assert_eq!(
        manager.enable(),
        Err(GatewayExposureError::StateUnavailable)
    );
    assert!(provider.calls.lock().expect("calls").is_empty());
    *store.exposure.lock().expect("exposure") =
        Some(exposure("https://inference.example.ts.net", 'a'));
    assert_eq!(manager.enable(), Err(GatewayExposureError::AlreadyEnabled));
    assert!(provider.calls.lock().expect("calls").is_empty());
}

// Commits a successful enable and compensates every failed persistence boundary.
#[test]
fn manager_enable_commits_or_restores_disabled_provider_state() {
    let (manager, store, _, _) = manager_environment(None);
    let enabled = manager.enable().expect("enable");
    assert_eq!(
        store.exposure.lock().expect("exposure").as_ref(),
        Some(&enabled)
    );

    let (manager, store, _, provider) = manager_environment(None);
    store.fail_replacements(1);
    assert_eq!(
        manager.enable(),
        Err(GatewayExposureError::StateUnavailable)
    );
    assert_eq!(*provider.live.lock().expect("live"), None);
    assert_eq!(
        provider.calls.lock().expect("calls").as_slice(),
        ["enable", &format!("disable:{}", "a".repeat(64))]
    );

    let (manager, store, _, provider) = manager_environment(None);
    store.fail_replacements(1);
    provider.fail_disables(1);
    assert_eq!(
        manager.enable(),
        Err(GatewayExposureError::RollbackIncomplete)
    );
    assert!(provider.live.lock().expect("live").is_some());
}

// Preserves durable state when provider disable is denied and clears it only on success.
#[test]
fn manager_disable_requires_exact_provider_identity_before_commit() {
    let (manager, _, _, provider) = manager_environment(None);
    assert_eq!(manager.disable(), Err(GatewayExposureError::NotEnabled));
    assert!(provider.calls.lock().expect("calls").is_empty());

    let expected = exposure("https://inference.example.ts.net", 'a');
    let (manager, store, _, provider) = manager_environment(Some(expected.clone()));
    *provider.live.lock().expect("live") = Some(expected.clone());
    provider.fail_disables(1);
    assert_eq!(
        manager.disable(),
        Err(GatewayExposureError::ProviderUnavailable)
    );
    assert_eq!(
        store.exposure.lock().expect("exposure").as_ref(),
        Some(&expected)
    );
    assert!(store.replacements.lock().expect("replacements").is_empty());
    manager.disable().expect("disable");
    assert_eq!(*store.exposure.lock().expect("exposure"), None);
}

// Replays one leased exact disable from absence and rejects replacement before provider mutation.
#[test]
fn manager_matching_disable_replays_absence_and_rejects_identity_drift() {
    let expected = exposure("https://inference.example.ts.net", 'a');
    let expected_sha256 = expected.configuration_sha256().clone();
    let (manager, store, _, provider) = manager_environment(Some(expected.clone()));
    *provider.live.lock().expect("live") = Some(expected);

    manager
        .disable_matching(&expected_sha256)
        .expect("matching disable");
    manager
        .disable_matching(&expected_sha256)
        .expect("absent-state replay");

    assert_eq!(*store.exposure.lock().expect("exposure"), None);
    assert_eq!(
        provider.calls.lock().expect("calls").as_slice(),
        [format!("disable:{}", expected_sha256.as_str())]
    );
    assert_eq!(store.replacements.lock().expect("replacements").len(), 1);

    let replacement = exposure("https://replacement.example.ts.net", 'b');
    let (manager, store, _, provider) = manager_environment(Some(replacement.clone()));
    *provider.live.lock().expect("live") = Some(replacement.clone());
    assert_eq!(
        manager.disable_matching(&expected_sha256),
        Err(GatewayExposureError::ProviderIdentityChanged)
    );
    assert_eq!(
        store.exposure.lock().expect("exposure").as_ref(),
        Some(&replacement)
    );
    assert!(provider.calls.lock().expect("calls").is_empty());
    assert!(store.replacements.lock().expect("replacements").is_empty());
}

// Restores the identical provider identity when durable disable commit fails.
#[test]
fn manager_disable_commit_failure_requires_exact_compensation() {
    let expected = exposure("https://inference.example.ts.net", 'a');
    let (manager, store, _, provider) = manager_environment(Some(expected.clone()));
    *provider.live.lock().expect("live") = Some(expected.clone());
    store.fail_replacements(1);
    assert_eq!(
        manager.disable(),
        Err(GatewayExposureError::StateUnavailable)
    );
    assert_eq!(
        provider.live.lock().expect("live").as_ref(),
        Some(&expected)
    );
    assert_eq!(
        store.exposure.lock().expect("exposure").as_ref(),
        Some(&expected)
    );

    let different = exposure("https://different.example.ts.net", 'b');
    let (manager, store, _, provider) = manager_environment(Some(expected.clone()));
    *provider.live.lock().expect("live") = Some(expected.clone());
    *provider.enabled_value.lock().expect("enabled value") = different;
    store.fail_replacements(1);
    assert_eq!(
        manager.disable(),
        Err(GatewayExposureError::RollbackIncomplete)
    );

    let (manager, store, _, provider) = manager_environment(Some(expected.clone()));
    *provider.live.lock().expect("live") = Some(expected);
    store.fail_replacements(1);
    provider.fail_enables(1);
    assert_eq!(
        manager.disable(),
        Err(GatewayExposureError::RollbackIncomplete)
    );
}
