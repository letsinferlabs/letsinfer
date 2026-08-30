// SPDX-License-Identifier: AGPL-3.0-only

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs, os::unix::fs::PermissionsExt};

use li_core_application::{
    ApplicationCoreSetupMaterialProvider, CoreBenchmarkVerificationSnapshotSigner,
    CoreSetupBenchmarkSigningPaths, CoreSetupGatewayTrustPaths, CoreSetupIssuedBenchmarkSigning,
    CoreSetupIssuedMutualTlsTrust, CoreSetupIssuedPairingTrust, CoreSetupIssuedResidentTrust,
    CoreSetupMaterialEntropy, CoreSetupMaterialIo, CoreSetupMaterialPaths,
    CoreSetupMaterialProvider, CoreSetupMaterialPublication, CoreSetupMaterialPublicationObserver,
    CoreSetupNodeTrustPaths, CoreSetupPairingTrustPaths, CoreSetupPreparedIdentity,
    CoreSetupPreparedMaterial, CoreSetupProviderError, CoreSetupReceipt, CoreSetupRequest,
    CoreSetupResidentTrustIssuer, CoreSetupWatchdogTrustPaths, CoreWatchdogHealthTlsFiles,
    OpenSslCoreSetupResidentTrustIssuer, SetupEd25519CoreBenchmarkVerificationSnapshotSigner,
    SystemCoreSetupMaterialIo, SystemCoreSetupTrustWorkspaceIo, SystemCoreWatchdogHealthExchange,
};
use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeRole, Sha256Digest,
};
use li_core_update_manager::{
    CoreInstallation, CoreUpdateNodeRole, CoreUpdateServiceContext, CoreUpdateServicePlatform,
    CoreVersion,
};
use li_gateway_manager::{
    GatewayNativeTlsFileSet, GatewayNativeTlsServerConfiguration, SystemGatewayNativeFileIo,
};
use li_node_manager::{
    NodePrivateRemoteTlsConfiguration, NodePrivateRemoteTlsFileSet,
    SystemNodePrivateRemoteTlsFileProvider,
};
use li_pairing_manager::{
    PairingError, PairingNativeCommand, PairingNativeCommandOutput, PairingNativeCommandRunner,
    PairingNativeProcess, SystemPairingNativeCommandRunner,
};
use li_watchdog_manager::{
    SystemWatchdogTlsFileProvider, WatchdogControllerAllowlist, WatchdogRustlsServerConfiguration,
    WatchdogTlsFileSet,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

// Supplies deterministic distinct entropy while recording every requested closure.
struct EntropyMock {
    calls: AtomicUsize,
}

impl CoreSetupMaterialEntropy for EntropyMock {
    // Fills one complete destination with its one-based call identity.
    fn fill(&self, destination: &mut [u8]) -> Result<(), CoreSetupProviderError> {
        let value = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        destination.fill(u8::try_from(value).expect("bounded call"));
        Ok(())
    }
}

// Issues one fixed bounded trust package and records whether replay reinvokes it.
struct IssuerMock {
    calls: AtomicUsize,
}

// Fails exactly one secret-free durable publication boundary and records every reached event.
struct PublicationObserver {
    fail_at: Option<usize>,
    events: Mutex<Vec<CoreSetupMaterialPublication>>,
}

impl CoreSetupMaterialPublicationObserver for PublicationObserver {
    // Records one durable event and injects a crash after the selected publication.
    fn did_publish(
        &self,
        publication: CoreSetupMaterialPublication,
        publication_index: usize,
    ) -> Result<(), CoreSetupProviderError> {
        self.events.lock().expect("events").push(publication);
        if self.fail_at == Some(publication_index) {
            return Err(CoreSetupProviderError::recovery_required(
                "private material",
                "injected publication crash",
            ));
        }
        Ok(())
    }
}

// Returns one deterministic native failure without exposing its diagnostic sentinel.
struct NativeFailureRunner {
    timed_out: bool,
    calls: AtomicUsize,
}

// Runs real OpenSSL while rejecting any accidental native Ed25519 dependency.
struct NativeEd25519RejectingRunner;

impl PairingNativeCommandRunner for NativeEd25519RejectingRunner {
    // Rejects native Ed25519 commands and delegates the remaining P-256 trust work.
    fn run(
        &self,
        command: &PairingNativeCommand,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError> {
        assert!(!command
            .arguments()
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("ED25519")));
        SystemPairingNativeCommandRunner.run(command, timeout, maximum_output_bytes)
    }

    // Rejects the unrelated long-running publisher boundary.
    fn spawn(
        &self,
        _command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError> {
        Err(PairingError::DiscoveryUnavailable)
    }
}

impl PairingNativeCommandRunner for NativeFailureRunner {
    // Fails the first bounded shell-free issuance command in the selected native class.
    fn run(
        &self,
        _command: &PairingNativeCommand,
        _timeout: Duration,
        _maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PairingNativeCommandOutput::new(
            i32::from(!self.timed_out),
            Vec::new(),
            b"native-secret-sentinel".to_vec(),
            self.timed_out,
        ))
    }

    // Rejects the unrelated long-running publisher boundary.
    fn spawn(
        &self,
        _command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError> {
        Err(PairingError::DiscoveryUnavailable)
    }
}

impl CoreSetupResidentTrustIssuer for IssuerMock {
    // Returns one exact platform-closed resident trust package.
    fn issue(
        &self,
        request: &CoreSetupRequest,
        _identity: &CoreSetupPreparedIdentity,
    ) -> Result<CoreSetupIssuedResidentTrust, CoreSetupProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let pairing = CoreSetupIssuedPairingTrust::new(
            b"private-key".to_vec(),
            b"public-key".to_vec(),
            b"ca-certificate".to_vec(),
            b"control-certificate".to_vec(),
            digest('a'),
            digest('b'),
        )?;
        let watchdog = (request.context().platform() == CoreUpdateServicePlatform::Linux)
            .then(|| mutual_trust(b"watchdog"))
            .transpose()?;
        Ok(CoreSetupIssuedResidentTrust::new_with_benchmark_signing(
            benchmark_signing_trust()?,
            pairing,
            mutual_trust(b"node")?,
            mutual_trust(b"gateway")?,
            watchdog,
        ))
    }
}

// Returns one deterministic dedicated benchmark-signing identity.
fn benchmark_signing_trust() -> Result<CoreSetupIssuedBenchmarkSigning, CoreSetupProviderError> {
    CoreSetupIssuedBenchmarkSigning::new(
        b"benchmark-private-key".to_vec(),
        b"benchmark-public-key".to_vec(),
        digest('9'),
    )
}

// Returns one deterministic distinct mutual-TLS trust package for a resident role.
fn mutual_trust(prefix: &[u8]) -> Result<CoreSetupIssuedMutualTlsTrust, CoreSetupProviderError> {
    let value = |suffix: &[u8]| [prefix, suffix].concat();
    CoreSetupIssuedMutualTlsTrust::new(
        value(b"-ca-key"),
        value(b"-ca-certificate"),
        value(b"-server-certificate"),
        value(b"-server-key"),
        value(b"-client-certificate"),
        value(b"-client-key"),
        digest('c'),
        digest('d'),
    )
}

// Simulates one atomic no-follow material transaction with an authoritative winner.
#[derive(Default)]
struct MaterialIoMock {
    material: Mutex<Option<CoreSetupPreparedMaterial>>,
    creates: AtomicUsize,
    rollbacks: Mutex<Vec<Sha256Digest>>,
}

impl CoreSetupMaterialIo for MaterialIoMock {
    // Returns the exact retained closure for restart replay.
    fn read(
        &self,
        _receipt: &CoreSetupReceipt,
    ) -> Result<Option<CoreSetupPreparedMaterial>, CoreSetupProviderError> {
        Ok(self.material.lock().expect("material").clone())
    }

    // Installs one closure or returns the exact winner selected under the atomic lock.
    fn create(
        &self,
        receipt: &CoreSetupReceipt,
        paths: &CoreSetupMaterialPaths,
        prepared_identity: &CoreSetupPreparedIdentity,
        _pairing_secret: &[u8; 32],
        api_key: Option<&[u8; 32]>,
        trust: &CoreSetupIssuedResidentTrust,
        material_identity: &Sha256Digest,
    ) -> Result<CoreSetupPreparedMaterial, CoreSetupProviderError> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        let mut current = self.material.lock().expect("material");
        if let Some(material) = current.as_ref() {
            return Ok(material.clone());
        }
        let material = trust.prepared_material(
            receipt.clone(),
            paths,
            prepared_identity,
            api_key.is_some(),
            material_identity.clone(),
        )?;
        *current = Some(material.clone());
        Ok(material)
    }

    // Records receipt-bound rollback without inventing deletion targets.
    fn rollback(&self, receipt: &CoreSetupReceipt) -> Result<(), CoreSetupProviderError> {
        self.rollbacks
            .lock()
            .expect("rollbacks")
            .push(receipt.identity().clone());
        Ok(())
    }
}

// Returns one complete explicit private-material destination closure for a platform.
fn paths(platform: CoreUpdateServicePlatform) -> CoreSetupMaterialPaths {
    CoreSetupMaterialPaths::new(
        "/state/core.sqlite3".into(),
        "/trust/pairing.key".into(),
        "/trust/api.key".into(),
        CoreSetupPairingTrustPaths::new(
            "/trust/site.key".into(),
            "/trust/site.pub".into(),
            "/trust/site-ca.crt".into(),
            "/trust/node.crt".into(),
        ),
        CoreSetupNodeTrustPaths::new(
            "/trust/node-ca.key".into(),
            "/trust/node-ca.crt".into(),
            "/trust/node-server.crt".into(),
            "/trust/node-server.key".into(),
            "/trust/node-client.crt".into(),
            "/trust/node-client.key".into(),
        ),
        CoreSetupGatewayTrustPaths::new(
            "/trust/gateway-ca.key".into(),
            "/trust/gateway-ca.crt".into(),
            "/trust/gateway-server.crt".into(),
            "/trust/gateway-server.key".into(),
            "/trust/gateway-client.crt".into(),
            "/trust/gateway-client.key".into(),
        ),
        (platform == CoreUpdateServicePlatform::Linux).then(|| {
            CoreSetupWatchdogTrustPaths::new(
                "/trust/watchdog-ca.key".into(),
                "/trust/watchdog-ca.crt".into(),
                "/trust/watchdog-server.crt".into(),
                "/trust/watchdog-server.key".into(),
                "/trust/watchdog-controller.crt".into(),
                "/trust/watchdog-controller.key".into(),
                "/trust/watchdog-controllers.allow".into(),
            )
        }),
    )
    .expect("paths")
    .with_benchmark_signing(CoreSetupBenchmarkSigningPaths::new(
        "/trust/benchmark-signing.key".into(),
        "/trust/benchmark-signing.pub".into(),
    ))
    .expect("benchmark signing paths")
}

// Returns one exact setup request for a selected role.
fn request_for(platform: CoreUpdateServicePlatform, role: CoreUpdateNodeRole) -> CoreSetupRequest {
    CoreSetupRequest::new(
        digest('1'),
        CoreUpdateServiceContext::new(platform, role),
        CoreInstallation::new(CoreVersion::parse("1.0.0").expect("version"), digest('2')),
        DisplayName::parse("Home AI").expect("name"),
        NodeAddress::parse("homeai.local").expect("address"),
        li_core_application::CoreSetupNetworkPlan::new(
            "127.0.0.1:9770".parse().expect("private"),
            "127.0.0.1:9771".parse().expect("gateway private"),
            (role == CoreUpdateNodeRole::Main).then(|| "127.0.0.1:11434".parse().expect("public")),
            (platform == CoreUpdateServicePlatform::Linux)
                .then(|| "127.0.0.1:7443".parse().expect("watchdog")),
        ),
    )
}

// Returns one Linux setup request for focused role-bound tests.
fn request(role: CoreUpdateNodeRole) -> CoreSetupRequest {
    request_for(CoreUpdateServicePlatform::Linux, role)
}

// Returns one role-matched prepared identity.
fn identity(role: CoreUpdateNodeRole) -> CoreSetupPreparedIdentity {
    CoreSetupPreparedIdentity::new(
        CoreSetupReceipt::new(digest('3')),
        NodeId::parse(&"4".repeat(32)).expect("node"),
        MachineId::parse(&"5".repeat(32)).expect("machine"),
        InstallationId::parse(&"6".repeat(64)).expect("installation"),
        DisplayName::parse("Home AI").expect("name"),
        match role {
            CoreUpdateNodeRole::Main => NodeRole::Main,
            CoreUpdateNodeRole::Child => NodeRole::Child,
        },
        NodeAddress::parse("homeai.local").expect("address"),
    )
}

// Creates one provider and exposes its deterministic capability owners.
fn provider_for(
    platform: CoreUpdateServicePlatform,
) -> (
    ApplicationCoreSetupMaterialProvider,
    Arc<EntropyMock>,
    Arc<IssuerMock>,
    Arc<MaterialIoMock>,
) {
    let entropy = Arc::new(EntropyMock {
        calls: AtomicUsize::new(0),
    });
    let issuer = Arc::new(IssuerMock {
        calls: AtomicUsize::new(0),
    });
    let io = Arc::new(MaterialIoMock::default());
    (
        ApplicationCoreSetupMaterialProvider::new(
            paths(platform),
            entropy.clone(),
            issuer.clone(),
            io.clone(),
        ),
        entropy,
        issuer,
        io,
    )
}

// Creates one Linux provider for focused common-boundary tests.
fn provider() -> (
    ApplicationCoreSetupMaterialProvider,
    Arc<EntropyMock>,
    Arc<IssuerMock>,
    Arc<MaterialIoMock>,
) {
    provider_for(CoreUpdateServicePlatform::Linux)
}

// Provisions exact Linux and macOS standalone-main closures with platform-exact Watchdog trust.
#[test]
fn material_provider_enforces_the_role_exact_secret_boundary() {
    for platform in [
        CoreUpdateServicePlatform::Linux,
        CoreUpdateServicePlatform::Macos,
    ] {
        let (provider, entropy, issuer, io) = provider_for(platform);
        let material = provider
            .prepare(
                &request_for(platform, CoreUpdateNodeRole::Main),
                &identity(CoreUpdateNodeRole::Main),
            )
            .expect("material");
        assert!(material.api_key_file().is_some());
        assert!(material.benchmark_signing().is_some());
        assert_eq!(
            material.watchdog_trust().is_some(),
            platform == CoreUpdateServicePlatform::Linux
        );
        assert_eq!(entropy.calls.load(Ordering::SeqCst), 2);
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(io.creates.load(Ordering::SeqCst), 1);
    }
}

// Replays the authoritative closure without regenerating any secret or trust material.
#[test]
fn material_provider_restart_replay_is_quiet_and_exact() {
    let (provider, entropy, issuer, io) = provider();
    let request = request(CoreUpdateNodeRole::Main);
    let identity = identity(CoreUpdateNodeRole::Main);
    let first = provider.prepare(&request, &identity).expect("first");
    let replay = provider.prepare(&request, &identity).expect("replay");
    assert_eq!(first, replay);
    assert_eq!(entropy.calls.load(Ordering::SeqCst), 2);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(io.creates.load(Ordering::SeqCst), 1);
}

// Serializes divergent generated candidates behind one authoritative atomic I/O winner.
#[test]
fn concurrent_material_preparation_returns_one_exact_winner() {
    let (provider, _, _, _) = provider();
    let provider = Arc::new(provider);
    let mut threads = Vec::new();
    for _ in 0..8 {
        let provider = provider.clone();
        threads.push(std::thread::spawn(move || {
            provider
                .prepare(
                    &request(CoreUpdateNodeRole::Main),
                    &identity(CoreUpdateNodeRole::Main),
                )
                .expect("material")
        }));
    }
    let values = threads
        .into_iter()
        .map(|thread| thread.join().expect("thread"))
        .collect::<Vec<_>>();
    assert!(values.iter().all(|value| value == &values[0]));
}

// Delegates rollback with only the exact opaque receipt identity.
#[test]
fn material_rollback_is_receipt_bound_and_idempotent() {
    let (provider, _, _, io) = provider();
    let material = provider
        .prepare(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("material");
    provider.rollback(material.receipt()).expect("rollback");
    provider
        .rollback(material.receipt())
        .expect("rollback replay");
    assert_eq!(
        io.rollbacks.lock().expect("rollbacks").as_slice(),
        [
            material.receipt().identity().clone(),
            material.receipt().identity().clone()
        ]
    );
}

// Returns one repeated hexadecimal SHA-256 identity.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Returns one complete destination closure beneath a real owner-private temporary root.
fn system_paths(
    root: &std::path::Path,
    platform: CoreUpdateServicePlatform,
) -> CoreSetupMaterialPaths {
    system_paths_in(root, "trust", platform)
}

// Returns one complete destination closure under a selected normalized trust descendant.
fn system_paths_in(
    root: &std::path::Path,
    trust_directory: &str,
    platform: CoreUpdateServicePlatform,
) -> CoreSetupMaterialPaths {
    let trust = root.join(trust_directory);
    CoreSetupMaterialPaths::new(
        root.join("state/core.sqlite3"),
        trust.join("pairing.key"),
        trust.join("api.key"),
        CoreSetupPairingTrustPaths::new(
            trust.join("site.key"),
            trust.join("site.pub"),
            trust.join("site-ca.crt"),
            trust.join("node.crt"),
        ),
        CoreSetupNodeTrustPaths::new(
            trust.join("node-ca.key"),
            trust.join("node-ca.crt"),
            trust.join("node-server.crt"),
            trust.join("node-server.key"),
            trust.join("node-client.crt"),
            trust.join("node-client.key"),
        ),
        CoreSetupGatewayTrustPaths::new(
            trust.join("gateway-ca.key"),
            trust.join("gateway-ca.crt"),
            trust.join("gateway-server.crt"),
            trust.join("gateway-server.key"),
            trust.join("gateway-client.crt"),
            trust.join("gateway-client.key"),
        ),
        (platform == CoreUpdateServicePlatform::Linux).then(|| {
            CoreSetupWatchdogTrustPaths::new(
                trust.join("watchdog-ca.key"),
                trust.join("watchdog-ca.crt"),
                trust.join("watchdog-server.crt"),
                trust.join("watchdog-server.key"),
                trust.join("watchdog-controller.crt"),
                trust.join("watchdog-controller.key"),
                trust.join("watchdog-controllers.allow"),
            )
        }),
    )
    .expect("system paths")
    .with_benchmark_signing(CoreSetupBenchmarkSigningPaths::new(
        trust.join("benchmark-signing.key"),
        trust.join("benchmark-signing.pub"),
    ))
    .expect("benchmark signing paths")
}

// Proves production no-follow persistence, restart replay, and exact reverse rollback.
#[test]
fn system_material_io_publishes_replays_and_rolls_back_exact_created_files() {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let io = Arc::new(
        SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe { libc::geteuid() })
            .expect("system io"),
    );
    let provider = ApplicationCoreSetupMaterialProvider::new(
        system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
        Arc::new(EntropyMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(IssuerMock {
            calls: AtomicUsize::new(0),
        }),
        io,
    );
    let request = request(CoreUpdateNodeRole::Main);
    let identity = identity(CoreUpdateNodeRole::Main);
    let first = provider.prepare(&request, &identity).expect("material");
    assert_eq!(
        first,
        provider.prepare(&request, &identity).expect("replay")
    );
    for path in [
        first.pairing_setup_secret_file(),
        first.api_key_file().expect("API key"),
        first
            .benchmark_signing()
            .expect("benchmark signing")
            .private_key_file(),
        first
            .benchmark_signing()
            .expect("benchmark signing")
            .public_key_file(),
        first.pairing_trust().site_private_key_file(),
        first.pairing_trust().site_public_key_file(),
        first.pairing_trust().site_ca_certificate_file(),
        first.pairing_trust().local_control_certificate_file(),
    ] {
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
    }
    provider.rollback(first.receipt()).expect("rollback");
    assert!(!first.pairing_setup_secret_file().exists());
    assert!(!first.pairing_trust().site_private_key_file().exists());
}

// Rejects a symlinked descendant before publishing any private material.
#[test]
fn system_material_io_rejects_symlinked_parent_without_partial_publication() {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let outside = tempfile::tempdir().expect("outside");
    std::os::unix::fs::symlink(outside.path(), temporary.path().join("trust")).expect("symlink");
    let provider = ApplicationCoreSetupMaterialProvider::new(
        system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
        Arc::new(EntropyMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(IssuerMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(
            SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe {
                libc::geteuid()
            })
            .expect("system io"),
        ),
    );
    assert!(provider
        .prepare(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .is_err());
    assert_eq!(fs::read_dir(outside.path()).expect("outside").count(), 0);
}

// Rejects root, relative, and traversal-bearing material destinations before native work.
#[test]
fn material_paths_reject_non_normal_or_root_destinations() {
    for database in ["relative.sqlite3", "/", "/state/../core.sqlite3"] {
        assert!(CoreSetupMaterialPaths::new(
            database.into(),
            "/trust/pairing.key".into(),
            "/trust/api.key".into(),
            CoreSetupPairingTrustPaths::new(
                "/trust/site.key".into(),
                "/trust/site.pub".into(),
                "/trust/site-ca.crt".into(),
                "/trust/node.crt".into(),
            ),
            CoreSetupNodeTrustPaths::new(
                "/trust/node-ca.key".into(),
                "/trust/node-ca.crt".into(),
                "/trust/node-server.crt".into(),
                "/trust/node-server.key".into(),
                "/trust/node-client.crt".into(),
                "/trust/node-client.key".into(),
            ),
            CoreSetupGatewayTrustPaths::new(
                "/trust/gateway-ca.key".into(),
                "/trust/gateway-ca.crt".into(),
                "/trust/gateway-server.crt".into(),
                "/trust/gateway-server.key".into(),
                "/trust/gateway-client.crt".into(),
                "/trust/gateway-client.key".into(),
            ),
            Some(CoreSetupWatchdogTrustPaths::new(
                "/trust/watchdog-ca.key".into(),
                "/trust/watchdog-ca.crt".into(),
                "/trust/watchdog-server.crt".into(),
                "/trust/watchdog-server.key".into(),
                "/trust/watchdog-controller.crt".into(),
                "/trust/watchdog-controller.key".into(),
                "/trust/watchdog-controllers.allow".into(),
            )),
        )
        .is_err());
    }
    assert!(paths(CoreUpdateServicePlatform::Linux)
        .with_benchmark_signing(CoreSetupBenchmarkSigningPaths::new(
            "/trust/site.key".into(),
            "/trust/benchmark-signing.pub".into(),
        ))
        .is_err());
}

// Rejects a role-substituted prepared identity before entropy, issuance, or persistence.
#[test]
fn material_provider_rejects_identity_substitution_before_mutation() {
    let (provider, entropy, issuer, io) = provider();
    assert!(provider
        .prepare(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Child),
        )
        .is_err());
    assert_eq!(entropy.calls.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(io.creates.load(Ordering::SeqCst), 0);
}

// Rejects child setup because child trust is created only by a later pairing role transition.
#[test]
fn material_provider_rejects_initial_child_before_entropy_or_native_work() {
    let (provider, entropy, issuer, io) = provider();
    let error = provider
        .prepare(
            &request(CoreUpdateNodeRole::Child),
            &identity(CoreUpdateNodeRole::Child),
        )
        .expect_err("child setup must fail");
    assert_eq!(
        error,
        CoreSetupProviderError::rolled_back(
            "private material",
            "initial setup must provision a standalone main node",
        )
    );
    assert_eq!(entropy.calls.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(io.creates.load(Ordering::SeqCst), 0);
}

// Rejects missing or extra Linux Watchdog trust before entropy, issuance, or persistence.
#[test]
fn material_provider_rejects_platform_trust_substitution_before_mutation() {
    for (platform, paths) in [
        (
            CoreUpdateServicePlatform::Linux,
            paths(CoreUpdateServicePlatform::Macos),
        ),
        (
            CoreUpdateServicePlatform::Macos,
            paths(CoreUpdateServicePlatform::Linux),
        ),
    ] {
        let entropy = Arc::new(EntropyMock {
            calls: AtomicUsize::new(0),
        });
        let issuer = Arc::new(IssuerMock {
            calls: AtomicUsize::new(0),
        });
        let io = Arc::new(MaterialIoMock::default());
        let provider = ApplicationCoreSetupMaterialProvider::new(
            paths,
            entropy.clone(),
            issuer.clone(),
            io.clone(),
        );
        assert!(provider
            .prepare(
                &request_for(platform, CoreUpdateNodeRole::Main),
                &identity(CoreUpdateNodeRole::Main),
            )
            .is_err());
        assert_eq!(entropy.calls.load(Ordering::SeqCst), 0);
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(io.creates.load(Ordering::SeqCst), 0);
    }
}

// Reconciles successfully after an injected crash at every durable material publication.
#[test]
fn system_material_io_recovers_after_every_publication_boundary() {
    let publication_count = successful_publication_count();
    assert_eq!(publication_count, 57);
    for fail_at in 0..publication_count {
        let temporary = tempfile::tempdir().expect("temporary");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        let observer = Arc::new(PublicationObserver {
            fail_at: Some(fail_at),
            events: Mutex::new(Vec::new()),
        });
        let failing = ApplicationCoreSetupMaterialProvider::new(
            system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
            Arc::new(EntropyMock {
                calls: AtomicUsize::new(0),
            }),
            Arc::new(IssuerMock {
                calls: AtomicUsize::new(0),
            }),
            Arc::new(
                SystemCoreSetupMaterialIo::new_with_publication_observer(
                    temporary.path().to_path_buf(),
                    unsafe { libc::geteuid() },
                    observer,
                )
                .expect("failing I/O"),
            ),
        );
        assert!(failing
            .prepare(
                &request(CoreUpdateNodeRole::Main),
                &identity(CoreUpdateNodeRole::Main),
            )
            .is_err());
        let recovering = ApplicationCoreSetupMaterialProvider::new(
            system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
            Arc::new(EntropyMock {
                calls: AtomicUsize::new(0),
            }),
            Arc::new(IssuerMock {
                calls: AtomicUsize::new(0),
            }),
            Arc::new(
                SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe {
                    libc::geteuid()
                })
                .expect("recovering I/O"),
            ),
        );
        let material = recovering
            .prepare(
                &request(CoreUpdateNodeRole::Main),
                &identity(CoreUpdateNodeRole::Main),
            )
            .unwrap_or_else(|error| panic!("publication {fail_at} did not recover: {error:?}"));
        assert!(material_files(&material).iter().all(|path| path.exists()));
        recovering
            .rollback(material.receipt())
            .expect("recovered rollback");
    }
}

// Preserves exact pre-existing material and refuses to erase any receipt-created file after drift.
#[test]
fn system_material_rollback_preserves_preexisting_files_and_stops_on_drift() {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let trust_directory = temporary.path().join("trust");
    fs::create_dir(&trust_directory).expect("trust directory");
    fs::set_permissions(&trust_directory, fs::Permissions::from_mode(0o700))
        .expect("trust permissions");
    let preexisting = trust_directory.join("site.pub");
    fs::write(&preexisting, b"public-key").expect("pre-existing public key");
    fs::set_permissions(&preexisting, fs::Permissions::from_mode(0o600))
        .expect("public-key permissions");
    let provider = ApplicationCoreSetupMaterialProvider::new(
        system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
        Arc::new(EntropyMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(IssuerMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(
            SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe {
                libc::geteuid()
            })
            .expect("system I/O"),
        ),
    );
    let material = provider
        .prepare(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("material");
    provider.rollback(material.receipt()).expect("rollback");
    assert_eq!(
        fs::read(&preexisting).expect("preserved key"),
        b"public-key"
    );
    assert!(material_files(&material)
        .into_iter()
        .filter(|path| *path != preexisting.as_path())
        .all(|path| !path.exists()));

    let material = provider
        .prepare(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("second material");
    let allowlist = material
        .watchdog_trust()
        .expect("Watchdog trust")
        .controller_allowlist_file();
    fs::write(allowlist, b"drift\n").expect("drift");
    let error = provider
        .rollback(material.receipt())
        .expect_err("drift must stop rollback");
    assert_eq!(
        error,
        CoreSetupProviderError::recovery_required(
            "private material",
            "private material rollback target changed",
        )
    );
    assert_eq!(fs::read(allowlist).expect("drift retained"), b"drift\n");
    assert!(material_files(&material).iter().all(|path| path.exists()));
}

// Serializes production same and divergent candidates under one cross-process receipt lock.
#[test]
fn system_material_io_serializes_concurrent_same_and_divergent_candidates() {
    for divergent in [false, true] {
        let temporary = tempfile::tempdir().expect("temporary");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        let second_directory = if divergent { "alternate" } else { "trust" };
        let providers = ["trust", second_directory].map(|directory| {
            ApplicationCoreSetupMaterialProvider::new(
                system_paths_in(
                    temporary.path(),
                    directory,
                    CoreUpdateServicePlatform::Linux,
                ),
                Arc::new(EntropyMock {
                    calls: AtomicUsize::new(0),
                }),
                Arc::new(IssuerMock {
                    calls: AtomicUsize::new(0),
                }),
                Arc::new(
                    SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe {
                        libc::geteuid()
                    })
                    .expect("system I/O"),
                ),
            )
        });
        let threads = providers.map(|provider| {
            std::thread::spawn(move || {
                provider.prepare(
                    &request(CoreUpdateNodeRole::Main),
                    &identity(CoreUpdateNodeRole::Main),
                )
            })
        });
        let results = threads.map(|thread| thread.join().expect("thread"));
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let failures = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .collect::<Vec<_>>();
        assert_eq!(
            successes,
            if divergent { 1 } else { 2 },
            "unexpected failures: {failures:?}"
        );
        if !divergent {
            assert_eq!(
                results[0].as_ref().expect("first"),
                results[1].as_ref().expect("second")
            );
        }
        let winner = results.into_iter().find_map(Result::ok).expect("winner");
        SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe { libc::geteuid() })
            .expect("rollback I/O")
            .rollback(winner.receipt())
            .expect("rollback");
    }
}

// Returns the exact complete Linux publication count from the production I/O transaction.
fn successful_publication_count() -> usize {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let observer = Arc::new(PublicationObserver {
        fail_at: None,
        events: Mutex::new(Vec::new()),
    });
    let provider = ApplicationCoreSetupMaterialProvider::new(
        system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
        Arc::new(EntropyMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(IssuerMock {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(
            SystemCoreSetupMaterialIo::new_with_publication_observer(
                temporary.path().to_path_buf(),
                unsafe { libc::geteuid() },
                observer.clone(),
            )
            .expect("observed I/O"),
        ),
    );
    let material = provider
        .prepare(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("material");
    provider.rollback(material.receipt()).expect("rollback");
    let publication_count = observer.events.lock().expect("events").len();
    publication_count
}

// Returns every exact file in one platform-complete prepared material closure.
fn material_files(material: &CoreSetupPreparedMaterial) -> Vec<&std::path::Path> {
    let signing = material.benchmark_signing().expect("benchmark signing");
    let mut files = vec![
        material.pairing_setup_secret_file(),
        material.api_key_file().expect("API key"),
        signing.private_key_file(),
        signing.public_key_file(),
        material.pairing_trust().site_private_key_file(),
        material.pairing_trust().site_public_key_file(),
        material.pairing_trust().site_ca_certificate_file(),
        material.pairing_trust().local_control_certificate_file(),
        material.node_trust().authority_private_key_file(),
        material.node_trust().authority_certificate_file(),
        material.node_trust().server_certificate_file(),
        material.node_trust().server_private_key_file(),
        material.node_trust().client_certificate_file(),
        material.node_trust().client_private_key_file(),
        material.gateway_trust().authority_private_key_file(),
        material.gateway_trust().authority_certificate_file(),
        material.gateway_trust().server_certificate_file(),
        material.gateway_trust().server_private_key_file(),
        material.gateway_trust().relay_client_certificate_file(),
        material.gateway_trust().relay_client_private_key_file(),
    ];
    if let Some(watchdog) = material.watchdog_trust() {
        files.extend([
            watchdog.authority_private_key_file(),
            watchdog.authority_certificate_file(),
            watchdog.server_certificate_file(),
            watchdog.server_private_key_file(),
            watchdog.controller_certificate_file(),
            watchdog.controller_private_key_file(),
            watchdog.controller_allowlist_file(),
        ]);
    }
    files
}

// Rejects every closed-manifest role, target, digest, platform, and field mutation on replay.
#[test]
fn system_material_manifest_rejects_table_driven_mutation_matrix() {
    for mutation in [
        "missing-role",
        "extra-role",
        "substituted-role",
        "swapped-role-targets",
        "duplicate-target",
        "invalid-digest",
        "missing-watchdog-closure",
        "corrupt-benchmark-signing-identity",
        "extra-field",
    ] {
        let temporary = tempfile::tempdir().expect("temporary");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        let provider = ApplicationCoreSetupMaterialProvider::new(
            system_paths(temporary.path(), CoreUpdateServicePlatform::Linux),
            Arc::new(EntropyMock {
                calls: AtomicUsize::new(0),
            }),
            Arc::new(IssuerMock {
                calls: AtomicUsize::new(0),
            }),
            Arc::new(
                SystemCoreSetupMaterialIo::new(temporary.path().to_path_buf(), unsafe {
                    libc::geteuid()
                })
                .expect("system I/O"),
            ),
        );
        let material = provider
            .prepare(
                &request(CoreUpdateNodeRole::Main),
                &identity(CoreUpdateNodeRole::Main),
            )
            .expect("material");
        let manifest_file = temporary.path().join(format!(
            ".li_core_setup_material_{}.json",
            material.receipt().identity().as_str()
        ));
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_file).expect("manifest"))
                .expect("manifest JSON");
        match mutation {
            "missing-role" => document["files"]
                .as_array_mut()
                .expect("files")
                .retain(|file| file["role"] != "node_server_certificate"),
            "extra-role" => {
                let files = document["files"].as_array_mut().expect("files");
                let mut extra = files[0].clone();
                extra["role"] = "foreign_role".into();
                extra["target"] = "trust/foreign".into();
                files.push(extra);
            }
            "substituted-role" => {
                let file = document["files"]
                    .as_array_mut()
                    .expect("files")
                    .iter_mut()
                    .find(|file| file["role"] == "node_server_certificate")
                    .expect("Node role");
                file["role"] = "gateway_server_certificate".into();
            }
            "swapped-role-targets" => {
                let files = document["files"].as_array_mut().expect("files");
                let node = files
                    .iter()
                    .position(|file| file["role"] == "node_server_certificate")
                    .expect("Node role");
                let gateway = files
                    .iter()
                    .position(|file| file["role"] == "gateway_server_certificate")
                    .expect("Gateway role");
                let node_target = files[node]["target"].clone();
                files[node]["target"] = files[gateway]["target"].clone();
                files[gateway]["target"] = node_target;
            }
            "duplicate-target" => {
                let files = document["files"].as_array_mut().expect("files");
                files[1]["target"] = files[0]["target"].clone();
            }
            "invalid-digest" => {
                document["files"][0]["sha256"] = "native-secret-sentinel".into();
            }
            "missing-watchdog-closure" => {
                document["watchdog_trust"] = serde_json::Value::Null;
            }
            "corrupt-benchmark-signing-identity" => {
                document["benchmark_signing"]["public_key_sha256"] =
                    "native-secret-sentinel".into();
            }
            "extra-field" => {
                document["foreign"] = true.into();
            }
            _ => unreachable!("closed mutation matrix"),
        }
        fs::write(
            &manifest_file,
            serde_json::to_vec(&document).expect("encoded manifest"),
        )
        .expect("mutated manifest");
        let error = provider
            .prepare(
                &request(CoreUpdateNodeRole::Main),
                &identity(CoreUpdateNodeRole::Main),
            )
            .expect_err("mutation must fail");
        let diagnostic = format!("{error:?}");
        assert!(!diagnostic.contains(temporary.path().to_string_lossy().as_ref()));
        assert!(!diagnostic.contains("native-secret-sentinel"));
    }
}

// Exercises the production shell-free OpenSSL issuer and proves complete workspace cleanup.
#[test]
fn openssl_material_issuer_generates_verified_identity_and_cleans_workspace() {
    let Some(openssl) = openssl_path() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let issuer = OpenSslCoreSetupResidentTrustIssuer::new(
        openssl.clone(),
        temporary.path().join("workspaces"),
        unsafe { libc::geteuid() },
        Arc::new(SystemPairingNativeCommandRunner),
        Arc::new(SystemCoreSetupTrustWorkspaceIo),
    )
    .expect("issuer");
    let trust = issuer
        .issue(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("trust identity");
    let material_root = temporary.path().join("material");
    fs::create_dir(&material_root).expect("material root");
    fs::set_permissions(&material_root, fs::Permissions::from_mode(0o700))
        .expect("material permissions");
    let io = SystemCoreSetupMaterialIo::new(material_root.clone(), unsafe { libc::geteuid() })
        .expect("material I/O");
    let prepared_identity = identity(CoreUpdateNodeRole::Main);
    let material = io
        .create(
            &CoreSetupReceipt::new(digest('e')),
            &system_paths(&material_root, CoreUpdateServicePlatform::Linux),
            &prepared_identity,
            &[0x11; 32],
            Some(&[0x22; 32]),
            &trust,
            &digest('f'),
        )
        .expect("material");
    assert!(!material
        .pairing_trust()
        .public_key_sha256()
        .as_str()
        .is_empty());
    let signing = material.benchmark_signing().expect("benchmark signing");
    let public_der = Command::new(&openssl)
        .args(["pkey", "-pubin", "-in"])
        .arg(signing.public_key_file())
        .args(["-outform", "DER"])
        .output()
        .expect("benchmark signing public DER");
    assert!(public_der.status.success());
    assert_eq!(
        signing.public_key_sha256().as_str(),
        format!("{:x}", Sha256::digest(&public_der.stdout))
    );
    let signer = SetupEd25519CoreBenchmarkVerificationSnapshotSigner::new(
        signing.private_key_file().to_path_buf(),
        unsafe { libc::geteuid() },
    )
    .expect("production benchmark signer");
    assert_eq!(
        signer
            .public_key_sha256()
            .expect("production signing identity"),
        *signing.public_key_sha256()
    );
    let signing_payload = b"setup-issued benchmark signing integration";
    let (signing_identity, signature) =
        CoreBenchmarkVerificationSnapshotSigner::sign(&signer, signing_payload)
            .expect("production benchmark signature");
    assert_eq!(signing_identity, *signing.public_key_sha256());
    let public_key = public_der
        .stdout
        .strip_prefix(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ])
        .expect("Ed25519 public key");
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(signing_payload, &signature)
        .expect("verified production benchmark signature");
    let owner_user_id = unsafe { libc::geteuid() };
    let node = material.node_trust();
    let node_files = NodePrivateRemoteTlsFileSet::new(
        owner_user_id,
        node.server_certificate_file().to_path_buf(),
        node.server_private_key_file().to_path_buf(),
        node.authority_certificate_file().to_path_buf(),
    )
    .expect("Node file set");
    NodePrivateRemoteTlsConfiguration::load(&node_files, &SystemNodePrivateRemoteTlsFileProvider)
        .expect("Node TLS consumer");
    let gateway = material.gateway_trust();
    let gateway_files = GatewayNativeTlsFileSet::new(
        owner_user_id,
        gateway.server_certificate_file().to_path_buf(),
        gateway.server_private_key_file().to_path_buf(),
        gateway.authority_certificate_file().to_path_buf(),
        gateway.relay_client_certificate_file().to_path_buf(),
    )
    .expect("Gateway file set");
    GatewayNativeTlsServerConfiguration::load(&gateway_files, &SystemGatewayNativeFileIo)
        .expect("Gateway TLS consumer");
    let watchdog = material.watchdog_trust().expect("Watchdog trust");
    let watchdog_files = WatchdogTlsFileSet::new(
        owner_user_id,
        watchdog.server_certificate_file().to_path_buf(),
        watchdog.server_private_key_file().to_path_buf(),
        watchdog.authority_certificate_file().to_path_buf(),
    )
    .expect("Watchdog file set");
    WatchdogRustlsServerConfiguration::load(&watchdog_files, &SystemWatchdogTlsFileProvider)
        .expect("Watchdog TLS consumer");
    let health_files = CoreWatchdogHealthTlsFiles::new(
        owner_user_id,
        watchdog.authority_certificate_file().to_path_buf(),
        watchdog.controller_certificate_file().to_path_buf(),
        watchdog.controller_private_key_file().to_path_buf(),
    )
    .expect("health file set");
    SystemCoreWatchdogHealthExchange::load(&health_files).expect("Core health TLS consumer");
    let allowlist = WatchdogControllerAllowlist::parse(
        &fs::read(watchdog.controller_allowlist_file()).expect("allowlist"),
    )
    .expect("Watchdog allowlist consumer");
    assert_eq!(
        allowlist.installation_id(),
        prepared_identity.installation_id().as_str()
    );
    assert!(allowlist.authorizes(
        prepared_identity.node_id().as_str(),
        watchdog.controller_certificate_sha256().as_str(),
    ));
    assert_eq!(
        fs::read_dir(temporary.path().join("workspaces"))
            .expect("workspace root")
            .count(),
        0
    );
    io.rollback(material.receipt()).expect("rollback");
}

// Proves setup never delegates Ed25519 generation to platform OpenSSL implementations.
#[test]
fn rust_benchmark_signing_avoids_native_ed25519_dependency() {
    let Some(openssl) = openssl_path() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let workspace_root = temporary.path().join("workspaces");
    let issuer = OpenSslCoreSetupResidentTrustIssuer::new(
        openssl,
        workspace_root.clone(),
        unsafe { libc::geteuid() },
        Arc::new(NativeEd25519RejectingRunner),
        Arc::new(SystemCoreSetupTrustWorkspaceIo),
    )
    .expect("issuer");
    let trust = issuer
        .issue(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("Rust-issued benchmark signing identity");
    let material = trust
        .prepared_material(
            CoreSetupReceipt::new(digest('e')),
            &paths(CoreUpdateServicePlatform::Linux),
            &identity(CoreUpdateNodeRole::Main),
            true,
            digest('f'),
        )
        .expect("prepared material");
    assert!(!material
        .benchmark_signing()
        .expect("benchmark signing")
        .public_key_sha256()
        .as_str()
        .is_empty());
    assert_eq!(
        fs::read_dir(workspace_root)
            .expect("workspace root")
            .count(),
        0
    );
}

// Generates the exact macOS standalone-main trust closure without Linux Watchdog material.
#[test]
fn openssl_material_issuer_closes_the_macos_main_matrix() {
    let Some(openssl) = openssl_path() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let issuer = OpenSslCoreSetupResidentTrustIssuer::new(
        openssl,
        temporary.path().join("workspaces"),
        unsafe { libc::geteuid() },
        Arc::new(SystemPairingNativeCommandRunner),
        Arc::new(SystemCoreSetupTrustWorkspaceIo),
    )
    .expect("issuer");
    let trust = issuer
        .issue(
            &request_for(CoreUpdateServicePlatform::Macos, CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        )
        .expect("macOS trust");
    let material = trust
        .prepared_material(
            CoreSetupReceipt::new(digest('e')),
            &paths(CoreUpdateServicePlatform::Macos),
            &identity(CoreUpdateNodeRole::Main),
            true,
            digest('f'),
        )
        .expect("macOS material");
    assert!(material.api_key_file().is_some());
    assert!(material.watchdog_trust().is_none());
    assert_eq!(
        fs::read_dir(temporary.path().join("workspaces"))
            .expect("workspace root")
            .count(),
        0
    );
}

// Returns the first available production OpenSSL executable without shell discovery.
fn openssl_path() -> Option<std::path::PathBuf> {
    ["/opt/local/bin/openssl", "/usr/bin/openssl"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_file())
}

// Redacts native nonzero and timeout diagnostics and removes every known partial output.
#[test]
fn openssl_material_issuer_cleans_nonzero_timeout_and_stale_workspaces() {
    for timed_out in [false, true] {
        let temporary = tempfile::tempdir().expect("temporary");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        let workspace_root = temporary.path().join("workspaces");
        fs::create_dir(&workspace_root).expect("workspace root");
        fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
            .expect("workspace root permissions");
        let stale = workspace_root.join(format!(
            "setup-{}",
            identity(CoreUpdateNodeRole::Main)
                .installation_id()
                .as_str()
        ));
        fs::create_dir(&stale).expect("stale workspace");
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o700))
            .expect("stale workspace permissions");
        let stale_output = stale.join("li_site_private_key.pem");
        fs::write(&stale_output, b"stale").expect("stale output");
        fs::set_permissions(&stale_output, fs::Permissions::from_mode(0o600))
            .expect("stale output permissions");
        let runner = Arc::new(NativeFailureRunner {
            timed_out,
            calls: AtomicUsize::new(0),
        });
        let issuer = OpenSslCoreSetupResidentTrustIssuer::new(
            "/native/openssl".into(),
            workspace_root.clone(),
            unsafe { libc::geteuid() },
            runner.clone(),
            Arc::new(SystemCoreSetupTrustWorkspaceIo),
        )
        .expect("issuer");
        let error = match issuer.issue(
            &request(CoreUpdateNodeRole::Main),
            &identity(CoreUpdateNodeRole::Main),
        ) {
            Ok(_) => panic!("native failure unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            CoreSetupProviderError::rolled_back(
                "private material",
                "OpenSSL trust issuance failed",
            )
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        assert!(!format!("{error:?}").contains("native-secret-sentinel"));
        assert_eq!(
            fs::read_dir(&workspace_root)
                .expect("workspace root")
                .count(),
            0
        );
    }
}

// Refuses to erase a foreign stale workspace entry before any native command can run.
#[test]
fn openssl_material_issuer_preserves_unknown_stale_workspace_entries() {
    let temporary = tempfile::tempdir().expect("temporary");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("root permissions");
    let workspace_root = temporary.path().join("workspaces");
    fs::create_dir(&workspace_root).expect("workspace root");
    fs::set_permissions(&workspace_root, fs::Permissions::from_mode(0o700))
        .expect("workspace root permissions");
    let workspace = workspace_root.join(format!(
        "setup-{}",
        identity(CoreUpdateNodeRole::Main)
            .installation_id()
            .as_str()
    ));
    fs::create_dir(&workspace).expect("workspace");
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))
        .expect("workspace permissions");
    let foreign = workspace.join("foreign-file");
    fs::write(&foreign, b"preserve").expect("foreign file");
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).expect("foreign permissions");
    let runner = Arc::new(NativeFailureRunner {
        timed_out: false,
        calls: AtomicUsize::new(0),
    });
    let issuer = OpenSslCoreSetupResidentTrustIssuer::new(
        "/native/openssl".into(),
        workspace_root,
        unsafe { libc::geteuid() },
        runner.clone(),
        Arc::new(SystemCoreSetupTrustWorkspaceIo),
    )
    .expect("issuer");
    let error = match issuer.issue(
        &request(CoreUpdateNodeRole::Main),
        &identity(CoreUpdateNodeRole::Main),
    ) {
        Ok(_) => panic!("foreign workspace unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        CoreSetupProviderError::recovery_required(
            "private material",
            "OpenSSL trust workspace recovery is ambiguous",
        )
    );
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(foreign).expect("foreign retained"), b"preserve");
}
