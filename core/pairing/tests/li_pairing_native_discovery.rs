// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeIdentity, NodeRole,
    Sha256Digest, UnixMilliseconds,
};
use li_pairing_manager::{
    NativePairingDiscoveryBrowser, NativePairingDiscoveryProvider, PairingCandidate, PairingClock,
    PairingContext, PairingCredentials, PairingDirectLinkProvider, PairingDiscoveryMode,
    PairingDiscoveryPlatform, PairingError, PairingManager, PairingMaterialProvider,
    PairingMembershipState, PairingMode, PairingNativeCommand, PairingNativeCommandOutput,
    PairingNativeCommandRunner, PairingNativeProcess, PairingRecord, PairingReplayRecord,
    PairingSetupCodeProvider, PairingStore, PairingTrustProvider, PairingWindowRequest,
    SystemPairingNativeCommandRunner, VersionedPairingRecord, PAIRING_DISCOVERY_PORT,
    PAIRING_DISCOVERY_SERVICE_TYPE,
};

// Captures one deterministic publisher lifecycle.
#[derive(Default)]
struct MockProcessState {
    fail_start: AtomicBool,
    fail_stop: AtomicBool,
    startup_checks: AtomicUsize,
    stops: AtomicUsize,
    drops: AtomicUsize,
}

// Presents one process state through the production publisher interface.
struct MockProcess {
    state: Arc<MockProcessState>,
}

impl PairingNativeProcess for MockProcess {
    // Records startup proof and returns the configured result without sleeping.
    fn require_running(&mut self, _startup_timeout: Duration) -> Result<(), PairingError> {
        self.state.startup_checks.fetch_add(1, Ordering::SeqCst);
        if self.state.fail_start.load(Ordering::SeqCst) {
            return Err(PairingError::DiscoveryUnavailable);
        }
        Ok(())
    }

    // Records exact cleanup and returns the configured bounded failure.
    fn stop(&mut self, _shutdown_timeout: Duration) -> Result<(), PairingError> {
        self.state.stops.fetch_add(1, Ordering::SeqCst);
        if self.state.fail_stop.load(Ordering::SeqCst) {
            return Err(PairingError::DiscoveryUnavailable);
        }
        Ok(())
    }
}

impl Drop for MockProcess {
    // Records release of the process owner after every lifecycle exit.
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}

// Supplies deterministic native process and command results.
#[derive(Default)]
struct MockRunner {
    spawned: Mutex<Vec<PairingNativeCommand>>,
    run: Mutex<Vec<PairingNativeCommand>>,
    processes: Mutex<VecDeque<Arc<MockProcessState>>>,
    outputs: Mutex<VecDeque<Result<PairingNativeCommandOutput, PairingError>>>,
}

impl MockRunner {
    // Queues one publisher process state.
    fn push_process(&self, state: Arc<MockProcessState>) {
        self.processes.lock().expect("processes").push_back(state);
    }

    // Queues one native command result.
    fn push_output(&self, output: Result<PairingNativeCommandOutput, PairingError>) {
        self.outputs.lock().expect("outputs").push_back(output);
    }
}

impl PairingNativeCommandRunner for MockRunner {
    // Records exact browse argv and returns its next deterministic output.
    fn run(
        &self,
        command: &PairingNativeCommand,
        _timeout: Duration,
        _maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError> {
        self.run.lock().expect("run commands").push(command.clone());
        self.outputs
            .lock()
            .expect("outputs")
            .pop_front()
            .unwrap_or(Err(PairingError::DiscoveryUnavailable))
    }

    // Records exact publisher argv and returns its next deterministic owner.
    fn spawn(
        &self,
        command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError> {
        self.spawned
            .lock()
            .expect("spawned commands")
            .push(command.clone());
        let state = self
            .processes
            .lock()
            .expect("processes")
            .pop_front()
            .ok_or(PairingError::DiscoveryUnavailable)?;
        Ok(Box::new(MockProcess { state }))
    }
}

// Supplies one stable test clock.
struct TestClock(AtomicU64);

impl PairingClock for TestClock {
    // Returns the exact configured test timestamp.
    fn now(&self) -> Result<UnixMilliseconds, PairingError> {
        Ok(UnixMilliseconds::new(self.0.load(Ordering::SeqCst)))
    }
}

// Supplies deterministic unique material without accessing host entropy.
struct TestMaterial(AtomicU8);

impl PairingMaterialProvider for TestMaterial {
    // Fills each pairing value with one monotonically changing byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError> {
        destination.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Derives one deterministic setup code for invitation publication tests.
struct TestSetupCode;

impl PairingSetupCodeProvider for TestSetupCode {
    // Returns one fixed eight-digit value without retaining plaintext state.
    fn derive(
        &self,
        _installation_id: &InstallationId,
        _invite_id: &li_core_interface::PairingInviteId,
        _nonce: &Sha256Digest,
        _salt: &[u8; 16],
    ) -> Result<[u8; 8], PairingError> {
        Ok(*b"12345678")
    }
}

// Refuses unused direct-link work in publication tests.
struct UnusedDirectLink;

impl PairingDirectLinkProvider for UnusedDirectLink {
    // Makes accidental direct-link use visible to the test.
    fn verify(
        &self,
        _interface: &li_core_interface::NetworkInterfaceName,
        _peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        Err(PairingError::DirectLinkUnavailable)
    }
}

// Refuses unused trust work in publication tests.
struct UnusedTrust;

impl PairingTrustProvider for UnusedTrust {
    // Makes accidental proof verification visible to the test.
    fn verify_candidate(
        &self,
        _public_key: &[u8],
        _transcript: &[u8],
        _signature: &[u8],
    ) -> Result<Sha256Digest, PairingError> {
        Err(PairingError::TrustUnavailable)
    }

    // Makes accidental credential issuance visible to the test.
    fn issue_membership(
        &self,
        _context: &PairingContext,
        _candidate: &PairingCandidate,
        _public_key_fingerprint: &Sha256Digest,
        _state: PairingMembershipState,
        _approval_expires_at: Option<UnixMilliseconds>,
    ) -> Result<PairingCredentials, PairingError> {
        Err(PairingError::TrustUnavailable)
    }
}

// Persists the bounded invitation state required by native discovery manager tests.
#[derive(Default)]
struct DiscoveryPairingStore {
    records: Mutex<BTreeMap<String, (PairingRecord, u64)>>,
    replays: Mutex<BTreeMap<String, PairingReplayRecord>>,
}

impl PairingStore for DiscoveryPairingStore {
    // Creates one absent invitation.
    fn create(&self, record: PairingRecord) -> Result<VersionedPairingRecord, PairingError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        if records.contains_key(record.invite_id().as_str()) {
            return Err(PairingError::StoreConflict);
        }
        let replay = PairingReplayRecord::open(&record)?;
        self.replays
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .insert(
                replay.identity().idempotency_sha256().as_str().to_string(),
                replay,
            );
        records.insert(record.invite_id().as_str().to_string(), (record.clone(), 1));
        VersionedPairingRecord::new(record, 1)
    }

    // Reads one exact invitation.
    fn pairing(
        &self,
        invite_id: &li_core_interface::PairingInviteId,
    ) -> Result<Option<VersionedPairingRecord>, PairingError> {
        self.records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .get(invite_id.as_str())
            .map(|(record, revision)| VersionedPairingRecord::new(record.clone(), *revision))
            .transpose()
    }

    // Resolves one exact durable open replay mapping.
    fn replay(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<PairingReplayRecord>, PairingError> {
        Ok(self
            .replays
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .get(idempotency_sha256.as_str())
            .cloned())
    }

    // Lists the caller-bounded invitation set.
    fn pairings(
        &self,
        maximum_results: usize,
    ) -> Result<Vec<VersionedPairingRecord>, PairingError> {
        let records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        if records.len() > maximum_results {
            return Err(PairingError::StoreCorrupt);
        }
        records
            .values()
            .map(|(record, revision)| VersionedPairingRecord::new(record.clone(), *revision))
            .collect()
    }

    // Replaces one exact observed invitation.
    fn replace(
        &self,
        record: PairingRecord,
        expected_revision: u64,
    ) -> Result<VersionedPairingRecord, PairingError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        let (_, revision) = records
            .get(record.invite_id().as_str())
            .ok_or(PairingError::NotFound)?;
        if *revision != expected_revision {
            return Err(PairingError::StoreConflict);
        }
        let revision = revision.checked_add(1).ok_or(PairingError::StoreCorrupt)?;
        records.insert(
            record.invite_id().as_str().to_string(),
            (record.clone(), revision),
        );
        VersionedPairingRecord::new(record, revision)
    }

    // Removes one just-created invitation and replay mapping after publication failure.
    fn rollback_create(
        &self,
        record: &PairingRecord,
        expected_revision: u64,
    ) -> Result<(), PairingError> {
        self.delete(record.invite_id(), expected_revision)?;
        self.replays
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?
            .remove(record.open_replay().idempotency_sha256().as_str());
        Ok(())
    }

    // Deletes one exact observed invitation.
    fn delete(
        &self,
        invite_id: &li_core_interface::PairingInviteId,
        expected_revision: u64,
    ) -> Result<(), PairingError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PairingError::StoreUnavailable)?;
        if records
            .get(invite_id.as_str())
            .is_none_or(|(_, revision)| *revision != expected_revision)
        {
            return Err(PairingError::StoreConflict);
        }
        records.remove(invite_id.as_str());
        Ok(())
    }
}

// Returns one canonical local pairing context.
fn context() -> PairingContext {
    PairingContext::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("node"),
            MachineId::parse(&"2".repeat(32)).expect("machine"),
            InstallationId::parse(&"3".repeat(64)).expect("installation"),
        ),
        NodeRole::Main,
        DisplayName::parse("Home AI").expect("display name"),
        NodeAddress::parse("homeai.local").expect("address"),
        9_770,
        Sha256Digest::parse(&"4".repeat(64)).expect("public key"),
        Sha256Digest::parse(&"5".repeat(64)).expect("certificate"),
    )
}

// Returns one manager composed with the real native publication provider.
fn manager(provider: Arc<NativePairingDiscoveryProvider>) -> PairingManager {
    PairingManager::new(
        context(),
        provider,
        Arc::new(UnusedDirectLink),
        Arc::new(UnusedTrust),
        Arc::new(TestMaterial(AtomicU8::new(1))),
        Arc::new(TestSetupCode),
        Arc::new(TestClock(AtomicU64::new(1_000))),
        Arc::new(DiscoveryPairingStore::default()),
    )
}

// Returns one canonical machine-output TXT sequence.
fn txt(certificate: char) -> String {
    format!(
        "\"expires=181000\" \"invite={}\" \"mode=lan\" \"protocol=1\" \"tls={}\"",
        "1".repeat(32),
        certificate.to_string().repeat(64)
    )
}

// Publishes exact shell-free Linux and macOS argv and stops only the owned invitation.
#[test]
fn native_publishers_use_exact_platform_commands_and_cleanup() {
    for (platform, executable, prefix) in [
        (
            PairingDiscoveryPlatform::LinuxAvahi,
            "/usr/bin/avahi-publish-service",
            Vec::<String>::new(),
        ),
        (
            PairingDiscoveryPlatform::MacosBonjour,
            "/usr/bin/dns-sd",
            vec!["-R".to_string()],
        ),
    ] {
        let runner = Arc::new(MockRunner::default());
        let process = Arc::new(MockProcessState::default());
        runner.push_process(process.clone());
        let provider = Arc::new(
            NativePairingDiscoveryProvider::new(
                platform,
                PathBuf::from(executable),
                runner.clone(),
            )
            .expect("provider"),
        );
        let manager = manager(provider.clone());
        let opened = manager
            .open(
                "open:publish",
                PairingWindowRequest::new(PairingMode::Lan, 180).expect("request"),
            )
            .expect("open");
        let invite_id = opened.value().invite_id().clone();
        let command = runner.spawned.lock().expect("spawned")[0].clone();
        assert_eq!(command.executable(), PathBuf::from(executable));
        let mut expected = prefix;
        expected.extend(match platform {
            PairingDiscoveryPlatform::LinuxAvahi => vec![
                "Let's Infer — Home AI".to_string(),
                PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
                PAIRING_DISCOVERY_PORT.to_string(),
            ],
            PairingDiscoveryPlatform::MacosBonjour => vec![
                "Let's Infer — Home AI".to_string(),
                PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
                "local".to_string(),
                PAIRING_DISCOVERY_PORT.to_string(),
            ],
        });
        expected.extend([
            "expires=181000".to_string(),
            format!("invite={}", "01".repeat(16)),
            "mode=lan".to_string(),
            "protocol=1".to_string(),
            format!("tls={}", "5".repeat(64)),
        ]);
        assert_eq!(command.arguments(), expected);
        assert_eq!(provider.active_publication_count().expect("count"), 1);
        manager.close(&invite_id).expect("close");
        assert_eq!(provider.active_publication_count().expect("count"), 0);
        assert_eq!(process.startup_checks.load(Ordering::SeqCst), 1);
        assert_eq!(process.stops.load(Ordering::SeqCst), 1);
    }
}

// Rejects publisher startup and reports explicit retirement failure without retaining state.
#[test]
fn native_publisher_fails_closed_and_releases_process_owners() {
    let runner = Arc::new(MockRunner::default());
    let startup = Arc::new(MockProcessState::default());
    startup.fail_start.store(true, Ordering::SeqCst);
    runner.push_process(startup.clone());
    let provider = Arc::new(
        NativePairingDiscoveryProvider::new(
            PairingDiscoveryPlatform::LinuxAvahi,
            PathBuf::from("/usr/bin/avahi-publish-service"),
            runner.clone(),
        )
        .expect("provider"),
    );
    assert_eq!(
        manager(provider.clone())
            .open(
                "open:start-failure",
                PairingWindowRequest::new(PairingMode::Lan, 180).expect("request"),
            )
            .expect_err("startup must fail"),
        PairingError::DiscoveryUnavailable
    );
    assert_eq!(provider.active_publication_count().expect("count"), 0);
    assert_eq!(startup.drops.load(Ordering::SeqCst), 1);

    let cleanup = Arc::new(MockProcessState::default());
    cleanup.fail_stop.store(true, Ordering::SeqCst);
    runner.push_process(cleanup.clone());
    let manager = manager(provider.clone());
    let opened = manager
        .open(
            "open:drop-cleanup",
            PairingWindowRequest::new(PairingMode::Lan, 180).expect("request"),
        )
        .expect("open");
    assert_eq!(
        provider
            .close(opened.value().invite_id())
            .expect_err("cleanup must report failure"),
        PairingError::DiscoveryUnavailable
    );
    assert_eq!(provider.active_publication_count().expect("count"), 0);
    assert_eq!(cleanup.stops.load(Ordering::SeqCst), 1);
}

// Decodes Avahi escapes, deduplicates address families, and prefers the LAN IPv4 route.
#[test]
fn avahi_browser_parses_bounded_records_and_exact_argv() {
    let runner = Arc::new(MockRunner::default());
    let output = format!(
        "=;enp1s0;IPv6;Let's\\032Infer\\032—\\032Lab;{};local;lab.local;2001:db8::2;{};{}\n\
         =;enp1s0;IPv4;Let's\\032Infer\\032—\\032Lab;{};local;lab.local;192.168.1.20;{};{}\n\
         =;enp1s0;IPv4;Let's\\032Infer\\032—\\032Configured;{};local;configured.local;192.168.1.21;9770;protocol=1 node={} role=main tls={}\n",
        PAIRING_DISCOVERY_SERVICE_TYPE,
        PAIRING_DISCOVERY_PORT,
        txt('a'),
        PAIRING_DISCOVERY_SERVICE_TYPE,
        PAIRING_DISCOVERY_PORT,
        txt('a'),
        PAIRING_DISCOVERY_SERVICE_TYPE,
        "9".repeat(32),
        "8".repeat(64)
    );
    runner.push_output(Ok(PairingNativeCommandOutput::new(
        124,
        output.into_bytes(),
        Vec::new(),
        false,
    )));
    let browser = NativePairingDiscoveryBrowser::new(
        PairingDiscoveryPlatform::LinuxAvahi,
        PathBuf::from("/usr/bin/avahi-browse"),
        runner.clone(),
    )
    .expect("browser");
    let records = browser.browse(5).expect("browse");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].display_name().as_str(), "Lab");
    assert_eq!(records[0].address().as_str(), "192.168.1.20");
    assert_eq!(records[0].mode(), PairingDiscoveryMode::Lan);
    assert_eq!(
        records[0].certificate_fingerprint().as_str(),
        "a".repeat(64)
    );
    let commands = runner.run.lock().expect("commands");
    assert_eq!(commands.len(), 1);
    assert_eq!(
        commands[0].executable(),
        PathBuf::from("/usr/bin/avahi-browse")
    );
    assert_eq!(
        commands[0].arguments(),
        ["-rpt", PAIRING_DISCOVERY_SERVICE_TYPE]
    );
}

// Resolves Bonjour instances with one fixed browse and one fixed lookup command.
#[test]
fn bonjour_browser_resolves_complete_records_with_exact_argv() {
    let runner = Arc::new(MockRunner::default());
    runner.push_output(Ok(PairingNativeCommandOutput::new(
        -1,
        format!(
            "13:00:00.000 Add 2 4 local. {}. Let's Infer — Mac\n",
            PAIRING_DISCOVERY_SERVICE_TYPE
        )
        .into_bytes(),
        Vec::new(),
        true,
    )));
    runner.push_output(Ok(PairingNativeCommandOutput::new(
        -1,
        format!(
            "Let's Infer — Mac.{}.local. can be reached at mac.local.:{} (interface 4)\n{}\n",
            PAIRING_DISCOVERY_SERVICE_TYPE,
            PAIRING_DISCOVERY_PORT,
            txt('b')
        )
        .into_bytes(),
        Vec::new(),
        true,
    )));
    let browser = NativePairingDiscoveryBrowser::new(
        PairingDiscoveryPlatform::MacosBonjour,
        PathBuf::from("/usr/bin/dns-sd"),
        runner.clone(),
    )
    .expect("browser");
    let records = browser.browse(3).expect("browse");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].display_name().as_str(), "Mac");
    assert_eq!(records[0].address().as_str(), "mac.local");
    assert_eq!(records[0].invite_id().as_str(), "1".repeat(32));
    let commands = runner.run.lock().expect("commands");
    assert_eq!(commands.len(), 2);
    assert_eq!(
        commands[0].arguments(),
        ["-B", PAIRING_DISCOVERY_SERVICE_TYPE, "local"]
    );
    assert_eq!(
        commands[1].arguments(),
        [
            "-L",
            "Let's Infer — Mac",
            PAIRING_DISCOVERY_SERVICE_TYPE,
            "local"
        ]
    );
}

// Rejects malformed, credential-bearing, and conflicting discovery output as one closed boundary.
#[test]
fn native_browser_rejects_malformed_and_conflicting_records() {
    for output in [
        format!(
            "=;eth0;IPv4;Home;{};local;home.local;192.168.1.2;{};{} \"credential=secret\"\n",
            PAIRING_DISCOVERY_SERVICE_TYPE,
            PAIRING_DISCOVERY_PORT,
            txt('c')
        ),
        format!(
            "=;eth0;IPv4;Home;{};local;home.local;192.168.1.2;{};{}\n\
             =;eth0;IPv6;Home;{};local;home.local;2001:db8::2;{};{}\n",
            PAIRING_DISCOVERY_SERVICE_TYPE,
            PAIRING_DISCOVERY_PORT,
            txt('c'),
            PAIRING_DISCOVERY_SERVICE_TYPE,
            PAIRING_DISCOVERY_PORT,
            txt('d')
        ),
        format!(
            "=;eth0;IPv4;Home;{};local;home.local;not-an-ip;{};{}\n",
            PAIRING_DISCOVERY_SERVICE_TYPE,
            PAIRING_DISCOVERY_PORT,
            txt('c')
        ),
    ] {
        let runner = Arc::new(MockRunner::default());
        runner.push_output(Ok(PairingNativeCommandOutput::new(
            0,
            output.into_bytes(),
            Vec::new(),
            false,
        )));
        let browser = NativePairingDiscoveryBrowser::new(
            PairingDiscoveryPlatform::LinuxAvahi,
            PathBuf::from("/usr/bin/avahi-browse"),
            runner,
        )
        .expect("browser");
        assert_eq!(
            browser.browse(2).expect_err("malformed record must fail"),
            PairingError::DiscoveryUnavailable
        );
    }
}

// Rejects unsafe executables, unbounded timeouts, and native runner failure before parsing.
#[test]
fn native_discovery_validates_composition_and_external_failures() {
    let runner = Arc::new(MockRunner::default());
    assert_eq!(
        NativePairingDiscoveryBrowser::new(
            PairingDiscoveryPlatform::LinuxAvahi,
            PathBuf::from("avahi-browse"),
            runner.clone(),
        )
        .err()
        .expect("relative executable must fail"),
        PairingError::InvalidRequest {
            reason: "pairing native executable must be an absolute non-shell path"
        }
    );
    let browser = NativePairingDiscoveryBrowser::new(
        PairingDiscoveryPlatform::LinuxAvahi,
        PathBuf::from("/usr/bin/avahi-browse"),
        runner.clone(),
    )
    .expect("browser");
    assert!(matches!(
        browser.browse(0),
        Err(PairingError::InvalidRequest { .. })
    ));
    runner.push_output(Err(PairingError::DiscoveryUnavailable));
    assert_eq!(
        browser.browse(1).expect_err("runner failure must fail"),
        PairingError::DiscoveryUnavailable
    );

    assert!(PairingNativeCommand::new(
        PathBuf::from("/bin/sh"),
        vec!["-c".to_string(), "unsafe".to_string()]
    )
    .is_err());
}

// Executes one harmless real command through the same bounded shell-free production runner.
#[test]
fn system_native_runner_executes_exact_argv_with_bounded_output() {
    let runner = SystemPairingNativeCommandRunner;
    let command = PairingNativeCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec!["pairing-ready".to_string()],
    )
    .expect("command");
    let output = runner
        .run(&command, Duration::from_secs(1), 64)
        .expect("run");
    assert_eq!(output.status(), 0);
    assert_eq!(output.stdout(), b"pairing-ready");
    assert!(output.stderr().is_empty());
    assert!(!output.timed_out());
    assert_eq!(
        runner
            .run(&command, Duration::from_secs(1), 4)
            .expect_err("oversized native output must fail"),
        PairingError::DiscoveryUnavailable
    );
}
