// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use li_core_interface::{InstallationId, NodeId, Sha256Digest};
use li_watchdog_manager::{
    decode_watchdog_protocol_frame, decode_watchdog_protocol_response,
    encode_watchdog_protocol_frame, encode_watchdog_protocol_request,
    SystemWatchdogTlsFileProvider, WatchdogControllerAllowlist, WatchdogControllerBinding,
    WatchdogControllerRegistry, WatchdogControllerSessionProvider,
    WatchdogControllerSnapshotProvider, WatchdogError, WatchdogLiveFanout,
    WatchdogLiveFanoutLimits, WatchdogProtectedEngine, WatchdogProtocolCapabilities,
    WatchdogProtocolDataError, WatchdogProtocolDataProvider, WatchdogProtocolDispatcher,
    WatchdogProtocolHistoryCursor, WatchdogProtocolListener, WatchdogProtocolListenerLimits,
    WatchdogProtocolRequest, WatchdogProtocolRequestKind, WatchdogProtocolResidentLifecycle,
    WatchdogProtocolResidentStatus, WatchdogProtocolResolution, WatchdogProtocolResponse,
    WatchdogProtocolSiteStatus, WatchdogRustlsServerConfiguration, WatchdogRustlsTcpLimits,
    WatchdogRustlsTcpServer, WatchdogSample, WatchdogTlsFile, WatchdogTlsFileProvider,
    WatchdogTlsFileSet,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SERVER_CERTIFICATE_PATH: &str = "/private/li_watchdog_server.crt";
const SERVER_PRIVATE_KEY_PATH: &str = "/private/li_watchdog_server.key";
const CONTROLLER_CA_PATH: &str = "/private/li_watchdog_controller_ca.crt";
const CONTROLLER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Owns one generated server hierarchy and three controller identities.
struct TestTlsIdentity {
    ca_certificate: Vec<u8>,
    server_certificate: Vec<u8>,
    server_private_key: Vec<u8>,
    controller_certificate: Vec<u8>,
    controller_private_key: Vec<u8>,
    alternate_controller_certificate: Vec<u8>,
    alternate_controller_private_key: Vec<u8>,
    untrusted_controller_certificate: Vec<u8>,
    untrusted_controller_private_key: Vec<u8>,
    controller_sha256: String,
}

// Stores one cloneable descriptor observation for the injected file provider.
#[derive(Clone)]
struct MockTlsFile {
    owner_user_id: u32,
    mode: u32,
    link_count: u64,
    is_regular_file: bool,
    bytes: Vec<u8>,
}

impl MockTlsFile {
    // Creates one safe owner-only regular-file observation.
    fn safe(bytes: Vec<u8>) -> Self {
        Self {
            owner_user_id: 501,
            mode: 0o600,
            link_count: 1,
            is_regular_file: true,
            bytes,
        }
    }

    // Converts the cloneable fixture into the provider's zeroing value.
    fn observation(&self) -> WatchdogTlsFile {
        WatchdogTlsFile::new(
            self.owner_user_id,
            self.mode,
            self.link_count,
            self.is_regular_file,
            self.bytes.clone(),
        )
    }
}

// Supplies strict TLS file observations from an in-memory path map.
struct MockTlsFileProvider {
    files: Mutex<BTreeMap<PathBuf, MockTlsFile>>,
}

impl MockTlsFileProvider {
    // Creates the exact safe identity map for one generated hierarchy.
    fn safe(identity: &TestTlsIdentity) -> Self {
        Self::new([
            (
                SERVER_CERTIFICATE_PATH,
                MockTlsFile::safe(identity.server_certificate.clone()),
            ),
            (
                SERVER_PRIVATE_KEY_PATH,
                MockTlsFile::safe(identity.server_private_key.clone()),
            ),
            (
                CONTROLLER_CA_PATH,
                MockTlsFile::safe(identity.ca_certificate.clone()),
            ),
        ])
    }

    // Creates one exact in-memory descriptor map.
    fn new<const N: usize>(files: [(&str, MockTlsFile); N]) -> Self {
        Self {
            files: Mutex::new(
                files
                    .into_iter()
                    .map(|(path, file)| (PathBuf::from(path), file))
                    .collect(),
            ),
        }
    }

    // Replaces one role-specific observation for a mutation case.
    fn replace(&self, path: &str, file: MockTlsFile) {
        self.files.lock().unwrap().insert(PathBuf::from(path), file);
    }
}

impl WatchdogTlsFileProvider for MockTlsFileProvider {
    // Returns one injected descriptor observation without normalizing unsafe metadata.
    fn read_no_follow(
        &self,
        path: &Path,
        _maximum_bytes: usize,
    ) -> Result<WatchdogTlsFile, WatchdogError> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(MockTlsFile::observation)
            .ok_or_else(|| WatchdogError::provider("test TLS files", "file is absent"))
    }
}

// Rejects every telemetry request because native TLS tests exercise only ping dispatch.
struct PingOnlyDataProvider;

impl WatchdogProtocolDataProvider for PingOnlyDataProvider {
    // Rejects an unused latest-sample request.
    fn latest(
        &self,
    ) -> Result<Option<li_watchdog_manager::WatchdogSample>, WatchdogProtocolDataError> {
        Ok(Some(protocol_sample(1)))
    }

    // Rejects an unused history request.
    fn history(
        &self,
        _resolution: WatchdogProtocolResolution,
        _start_unix_milliseconds: u64,
        _end_unix_milliseconds: u64,
    ) -> Result<Box<dyn WatchdogProtocolHistoryCursor>, WatchdogProtocolDataError> {
        Err(WatchdogProtocolDataError::Unavailable)
    }

    // Returns a complete fixed capability document if explicitly requested.
    fn capabilities(&self) -> Result<WatchdogProtocolCapabilities, WatchdogProtocolDataError> {
        Ok(WatchdogProtocolCapabilities::new(1_000, 10_000, 1).unwrap())
    }

    // Rejects an unused site-status request.
    fn site_status(
        &self,
        _binding: &li_watchdog_manager::WatchdogControllerBinding,
    ) -> Result<WatchdogProtocolSiteStatus, WatchdogProtocolDataError> {
        Err(WatchdogProtocolDataError::Unavailable)
    }

    // Returns a full-sized ready identity that crosses the native TLS close boundary.
    fn resident_status(&self) -> Result<WatchdogProtocolResidentStatus, WatchdogProtocolDataError> {
        WatchdogProtocolResidentStatus::ready(
            NodeId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            "test-core-release".to_string(),
            Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            InstallationId::parse(&"d".repeat(64)).unwrap(),
        )
        .map_err(|_| WatchdogProtocolDataError::Unavailable)
    }
}

// Resolves only the exact allowed leaf and advances its process-bound generation.
struct SequenceSessionProvider {
    certificate_sha256: String,
    next_generation: AtomicU64,
}

// Persists exact registry bytes in memory for native-listener composition tests.
struct MemoryControllerSnapshots {
    snapshot: Mutex<Option<Vec<u8>>>,
}

impl MemoryControllerSnapshots {
    // Creates one absent restart snapshot.
    fn new() -> Self {
        Self {
            snapshot: Mutex::new(None),
        }
    }
}

impl WatchdogControllerSnapshotProvider for MemoryControllerSnapshots {
    // Returns the complete current snapshot if one has been committed.
    fn load(&self) -> Result<Option<Vec<u8>>, WatchdogError> {
        Ok(self.snapshot.lock().unwrap().clone())
    }

    // Replaces only the exact snapshot previously observed by the registry.
    fn commit(
        &self,
        expected_snapshot: Option<&[u8]>,
        snapshot: &[u8],
    ) -> Result<(), WatchdogError> {
        let mut current = self.snapshot.lock().unwrap();
        if current.as_deref() != expected_snapshot {
            return Err(WatchdogError::provider(
                "test controller snapshot",
                "snapshot conflicts",
            ));
        }
        *current = Some(snapshot.to_vec());
        Ok(())
    }
}

impl SequenceSessionProvider {
    // Creates one monotonic session source for the accepted leaf identity.
    fn new(certificate_sha256: String) -> Self {
        Self {
            certificate_sha256,
            next_generation: AtomicU64::new(1),
        }
    }
}

impl WatchdogControllerSessionProvider for SequenceSessionProvider {
    // Returns a new exact binding only for the allowlisted certificate digest.
    fn binding_for_certificate(
        &self,
        certificate_sha256: &str,
    ) -> Result<WatchdogControllerBinding, WatchdogError> {
        if certificate_sha256 != self.certificate_sha256 {
            return Err(WatchdogError::provider(
                "test controller sessions",
                "certificate is unknown",
            ));
        }
        let generation = self.next_generation.fetch_add(1, Ordering::AcqRel);
        WatchdogControllerBinding::new(
            CONTROLLER_ID,
            certificate_sha256,
            generation,
            protected_target(generation),
        )
    }
}

// Proves injected metadata, references, and identity material all fail closed.
#[test]
fn rustls_configuration_closes_every_injected_identity_boundary() {
    let identity = tls_identity();
    let files = tls_file_set();
    WatchdogRustlsServerConfiguration::load(&files, &MockTlsFileProvider::safe(&identity)).unwrap();

    assert!(WatchdogTlsFileSet::new(
        501,
        PathBuf::from("relative.crt"),
        PathBuf::from(SERVER_PRIVATE_KEY_PATH),
        PathBuf::from(CONTROLLER_CA_PATH),
    )
    .is_err());
    assert!(WatchdogTlsFileSet::new(
        501,
        PathBuf::from(SERVER_CERTIFICATE_PATH),
        PathBuf::from(SERVER_CERTIFICATE_PATH),
        PathBuf::from(CONTROLLER_CA_PATH),
    )
    .is_err());
    for limits in [
        WatchdogRustlsTcpLimits::new(0, 1_000, 5),
        WatchdogRustlsTcpLimits::new(17, 1_000, 5),
        WatchdogRustlsTcpLimits::new(1, 10_001, 5),
        WatchdogRustlsTcpLimits::new(1, 1_000, 101),
    ] {
        assert!(limits.is_err());
    }

    let unsafe_keys = [
        MockTlsFile {
            owner_user_id: 502,
            ..MockTlsFile::safe(identity.server_private_key.clone())
        },
        MockTlsFile {
            mode: 0o640,
            ..MockTlsFile::safe(identity.server_private_key.clone())
        },
        MockTlsFile {
            link_count: 2,
            ..MockTlsFile::safe(identity.server_private_key.clone())
        },
        MockTlsFile {
            is_regular_file: false,
            ..MockTlsFile::safe(identity.server_private_key.clone())
        },
        MockTlsFile::safe(Vec::new()),
        MockTlsFile::safe(vec![b'x'; 128 * 1024 + 1]),
    ];
    for unsafe_key in unsafe_keys {
        let provider = MockTlsFileProvider::safe(&identity);
        provider.replace(SERVER_PRIVATE_KEY_PATH, unsafe_key);
        let error = WatchdogRustlsServerConfiguration::load(&files, &provider)
            .err()
            .unwrap();
        assert!(!error.to_string().contains(SERVER_PRIVATE_KEY_PATH));
    }

    let identity_mutations = [
        (
            SERVER_CERTIFICATE_PATH,
            MockTlsFile::safe(b"not a certificate\n".to_vec()),
        ),
        (
            SERVER_PRIVATE_KEY_PATH,
            MockTlsFile::safe(identity.controller_private_key.clone()),
        ),
        (
            CONTROLLER_CA_PATH,
            MockTlsFile::safe(identity.server_private_key.clone()),
        ),
    ];
    for (path, mutation) in identity_mutations {
        let provider = MockTlsFileProvider::safe(&identity);
        provider.replace(path, mutation);
        assert!(WatchdogRustlsServerConfiguration::load(&files, &provider).is_err());
    }

    let ephemeral_registry = Arc::new(
        WatchdogControllerRegistry::new(
            WatchdogControllerAllowlist::parse(
                format!(
                    "version=1\ninstallation_id={}\ncontroller={},{}\n",
                    "f".repeat(64),
                    CONTROLLER_ID,
                    identity.controller_sha256,
                )
                .as_bytes(),
            )
            .unwrap(),
            1,
        )
        .unwrap(),
    );
    let listener = Arc::new(WatchdogProtocolListener::new(
        Arc::new(WatchdogProtocolDispatcher::new(Arc::new(
            PingOnlyDataProvider,
        ))),
        ephemeral_registry,
        Arc::new(SequenceSessionProvider::new(
            identity.controller_sha256.clone(),
        )),
        WatchdogProtocolListenerLimits::new(1, 1, 100, 100).unwrap(),
    ));
    let tls = WatchdogRustlsServerConfiguration::load(
        &tls_file_set(),
        &MockTlsFileProvider::safe(&identity),
    )
    .unwrap();
    assert!(WatchdogRustlsTcpServer::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        listener,
        Arc::new(WatchdogLiveFanout::new(
            WatchdogLiveFanoutLimits::production(),
        )),
        tls,
        WatchdogRustlsTcpLimits::new(1, 100, 5).unwrap(),
    )
    .is_err());
}

// Proves production descriptor reads reject unsafe modes, symlinks, and hard links.
#[test]
fn system_tls_files_require_owner_only_no_follow_single_link_inputs() {
    let identity = tls_identity();
    let directory = tempdir().unwrap();
    let certificate = directory.path().join("server.crt");
    let private_key = directory.path().join("server.key");
    let controller_ca = directory.path().join("controller-ca.crt");
    write_private_file(&certificate, &identity.server_certificate);
    write_private_file(&private_key, &identity.server_private_key);
    write_private_file(&controller_ca, &identity.ca_certificate);
    let owner_user_id = unsafe { libc::geteuid() };
    let files = WatchdogTlsFileSet::new(
        owner_user_id,
        certificate.clone(),
        private_key.clone(),
        controller_ca.clone(),
    )
    .unwrap();
    let provider = SystemWatchdogTlsFileProvider;
    WatchdogRustlsServerConfiguration::load(&files, &provider).unwrap();

    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(WatchdogRustlsServerConfiguration::load(&files, &provider).is_err());
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600)).unwrap();

    let linked_certificate = directory.path().join("linked-server.crt");
    symlink(&certificate, &linked_certificate).unwrap();
    let symlink_files = WatchdogTlsFileSet::new(
        owner_user_id,
        linked_certificate,
        private_key.clone(),
        controller_ca.clone(),
    )
    .unwrap();
    assert!(WatchdogRustlsServerConfiguration::load(&symlink_files, &provider).is_err());

    let ca_hard_link = directory.path().join("controller-ca-copy.crt");
    fs::hard_link(&controller_ca, ca_hard_link).unwrap();
    assert!(WatchdogRustlsServerConfiguration::load(&files, &provider).is_err());
}

// Proves a real TLS 1.3 controller reaches the centralized ping dispatcher and shuts down cleanly.
#[test]
fn rustls_loopback_accepts_the_exact_controller_leaf_and_dispatches_ping() {
    let identity = tls_identity();
    let (server, worker) = running_server(&identity, 4, 1_000);
    let mut client = connect_controller(
        server.local_address().unwrap(),
        &identity,
        &identity.controller_certificate,
        &identity.controller_private_key,
    )
    .unwrap();
    let request = request_frame(7, WatchdogProtocolRequestKind::Ping { nonce: 77 });
    client.write_all(&request).unwrap();
    client.flush().unwrap();
    let response = read_response(&mut client).unwrap();
    assert!(matches!(
        response.kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::Pong { nonce: 77 }
    ));
    assert_eq!(
        client.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    server.shutdown().unwrap();
    worker.join().unwrap().unwrap();
}

// Proves one full resident response and TLS close notification arrive before native shutdown.
#[test]
fn rustls_loopback_flushes_resident_health_before_graceful_close() {
    let identity = tls_identity();
    let (server, worker) = running_server(&identity, 4, 1_000);
    let mut client = connect_controller(
        server.local_address().unwrap(),
        &identity,
        &identity.controller_certificate,
        &identity.controller_private_key,
    )
    .unwrap();
    client
        .write_all(&request_frame(
            17,
            WatchdogProtocolRequestKind::GetResidentStatus,
        ))
        .unwrap();
    client.flush().unwrap();
    let response = read_response(&mut client).unwrap();
    assert!(matches!(
        response.kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::ResidentStatus(status)
            if status.lifecycle() == WatchdogProtocolResidentLifecycle::Ready
                && status.core_release() == "test-core-release"
    ));
    let mut terminal = [0_u8; 1];
    assert_eq!(client.read(&mut terminal).unwrap(), 0);

    server.shutdown().unwrap();
    worker.join().unwrap().unwrap();
}

// Proves CA trust and exact allowlist identity are independent mandatory checks.
#[test]
fn rustls_loopback_rejects_unknown_and_untrusted_controller_leaves() {
    let identity = tls_identity();
    let (server, worker) = running_server(&identity, 4, 1_000);
    let address = server.local_address().unwrap();

    let mut unknown = connect_controller(
        address,
        &identity,
        &identity.alternate_controller_certificate,
        &identity.alternate_controller_private_key,
    )
    .unwrap();
    unknown
        .write_all(&request_frame(
            8,
            WatchdogProtocolRequestKind::Ping { nonce: 88 },
        ))
        .unwrap();
    unknown.flush().unwrap();
    assert!(read_response(&mut unknown).is_err());

    server.shutdown().unwrap();
    worker.join().unwrap().unwrap();

    let untrusted_sha256 = certificate_sha256(&identity.untrusted_controller_certificate);
    let (server, worker) = running_server_for_fingerprint(&identity, 4, 1_000, untrusted_sha256);
    let untrusted = connect_controller(
        server.local_address().unwrap(),
        &identity,
        &identity.untrusted_controller_certificate,
        &identity.untrusted_controller_private_key,
    );
    if let Ok(mut untrusted) = untrusted {
        let _ = untrusted.write_all(&request_frame(
            9,
            WatchdogProtocolRequestKind::Ping { nonce: 99 },
        ));
        let _ = untrusted.flush();
        assert!(read_response(&mut untrusted).is_err());
    }

    server.shutdown().unwrap();
    worker.join().unwrap().unwrap();
}

// Proves the absolute handshake deadline, worker bound, and shutdown interruption paths.
#[test]
fn rustls_tcp_bounds_half_open_connections_and_interrupts_workers() {
    let identity = tls_identity();
    let (timeout_server, timeout_worker) = running_server(&identity, 1, 60);
    let mut half_open = TcpStream::connect(timeout_server.local_address().unwrap()).unwrap();
    half_open
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    assert!(connection_closed(&mut half_open));
    timeout_server.shutdown().unwrap();
    timeout_worker.join().unwrap().unwrap();

    let (shutdown_server, shutdown_worker) = running_server(&identity, 1, 1_000);
    let address = shutdown_server.local_address().unwrap();
    let mut first = TcpStream::connect(address).unwrap();
    first
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    thread::sleep(Duration::from_millis(30));
    let mut bounded = TcpStream::connect(address).unwrap();
    bounded
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    assert!(connection_closed(&mut bounded));

    let began = Instant::now();
    shutdown_server.shutdown().unwrap();
    shutdown_worker.join().unwrap().unwrap();
    assert!(began.elapsed() < Duration::from_millis(500));
    assert!(connection_closed(&mut first));
}

// Proves malformed and oversized authenticated frames terminate without bypassing framing bounds.
#[test]
fn rustls_loopback_closes_malformed_and_oversized_post_handshake_frames() {
    let identity = tls_identity();
    let (server, worker) = running_server(&identity, 4, 1_000);
    let address = server.local_address().unwrap();

    let mut malformed = connect_controller(
        address,
        &identity,
        &identity.controller_certificate,
        &identity.controller_private_key,
    )
    .unwrap();
    malformed
        .write_all(&encode_watchdog_protocol_frame(&[0xff]).unwrap())
        .unwrap();
    malformed.flush().unwrap();
    let response = read_response(&mut malformed).unwrap();
    assert!(matches!(
        response.kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::Error {
            code: 400,
            message,
        } if message == "invalid protobuf request"
    ));

    let mut oversized = connect_controller(
        address,
        &identity,
        &identity.controller_certificate,
        &identity.controller_private_key,
    )
    .unwrap();
    oversized.write_all(&[0, 1, 0, 1]).unwrap();
    oversized.flush().unwrap();
    assert!(read_response(&mut oversized).is_err());

    server.shutdown().unwrap();
    worker.join().unwrap().unwrap();
}

// Proves a real retained mTLS subscription receives each shared fanout sample exactly once.
#[test]
fn rustls_loopback_streams_shared_resident_fanout_without_replay() {
    let identity = tls_identity();
    let (server, worker, fanout) =
        running_server_with_fingerprint(&identity, 4, 1_000, identity.controller_sha256.clone());
    fanout.publish(&protocol_sample(1)).unwrap();
    let mut client = connect_controller(
        server.local_address().unwrap(),
        &identity,
        &identity.controller_certificate,
        &identity.controller_private_key,
    )
    .unwrap();
    client
        .write_all(&request_frame(
            10,
            WatchdogProtocolRequestKind::Subscribe { history_seconds: 0 },
        ))
        .unwrap();
    client.flush().unwrap();
    assert!(matches!(
        read_response(&mut client).unwrap().kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::Latest(sample)
            if sample.sequence() == 1
    ));
    assert!(matches!(
        read_response(&mut client).unwrap().kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::HistoryComplete {
            through_sequence: 1
        }
    ));
    wait_for_subscriber(&fanout);

    fanout.publish(&protocol_sample(2)).unwrap();
    assert!(matches!(
        read_response(&mut client).unwrap().kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::Live(sample)
            if sample.sequence() == 2
    ));
    assert_eq!(
        fanout.publish(&protocol_sample(2)).unwrap().kind(),
        li_watchdog_manager::WatchdogLivePublishKind::Replayed
    );
    fanout.publish(&protocol_sample(3)).unwrap();
    assert!(matches!(
        read_response(&mut client).unwrap().kind(),
        li_watchdog_manager::WatchdogProtocolResponseKind::Live(sample)
            if sample.sequence() == 3
    ));

    server.shutdown().unwrap();
    worker.join().unwrap().unwrap();
}

// Generates one ephemeral CA, server, trusted controllers, and an unrelated controller.
fn tls_identity() -> TestTlsIdentity {
    let (ca_certificate, ca_key) = certificate_authority("li-watchdog-test-ca");
    let (server_certificate, server_private_key) = signed_identity(
        "watchdog.local",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca_certificate,
        &ca_key,
    );
    let (controller_certificate, controller_private_key) = signed_identity(
        "li-watchdog-controller",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca_certificate,
        &ca_key,
    );
    let (alternate_controller_certificate, alternate_controller_private_key) = signed_identity(
        "li-watchdog-other-controller",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca_certificate,
        &ca_key,
    );
    let (untrusted_ca, untrusted_ca_key) = certificate_authority("li-watchdog-untrusted-ca");
    let (untrusted_controller_certificate, untrusted_controller_private_key) = signed_identity(
        "li-watchdog-untrusted-controller",
        ExtendedKeyUsagePurpose::ClientAuth,
        &untrusted_ca,
        &untrusted_ca_key,
    );
    let ca_certificate = ca_certificate.pem().into_bytes();
    let controller_sha256 = certificate_sha256(&controller_certificate);
    TestTlsIdentity {
        ca_certificate,
        server_certificate,
        server_private_key,
        controller_certificate,
        controller_private_key,
        alternate_controller_certificate,
        alternate_controller_private_key,
        untrusted_controller_certificate,
        untrusted_controller_private_key,
        controller_sha256,
    }
}

// Creates one certificate authority with certificate-signing use only.
fn certificate_authority(common_name: &str) -> (Certificate, KeyPair) {
    let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    parameters.distinguished_name = distinguished_name(common_name);
    let key = KeyPair::generate().unwrap();
    let certificate = parameters.self_signed(&key).unwrap();
    (certificate, key)
}

// Creates one CA-signed server or controller identity with one exact extended use.
fn signed_identity(
    common_name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca_certificate: &Certificate,
    ca_key: &KeyPair,
) -> (Vec<u8>, Vec<u8>) {
    let names = if usage == ExtendedKeyUsagePurpose::ServerAuth {
        vec![common_name.to_string()]
    } else {
        Vec::new()
    };
    let mut parameters = CertificateParams::new(names).unwrap();
    parameters.extended_key_usages = vec![usage];
    parameters.distinguished_name = distinguished_name(common_name);
    let key = KeyPair::generate().unwrap();
    let certificate = parameters.signed_by(&key, ca_certificate, ca_key).unwrap();
    (
        certificate.pem().into_bytes(),
        key.serialize_pem().into_bytes(),
    )
}

// Creates one simple deterministic certificate subject.
fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

// Returns one lowercase SHA-256 identity for the leaf certificate DER.
fn certificate_sha256(certificate: &[u8]) -> String {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .next()
        .unwrap()
        .unwrap();
    lower_hex(&Sha256::digest(certificate.as_ref()))
}

// Creates the exact role-bound TLS file references used by injected tests.
fn tls_file_set() -> WatchdogTlsFileSet {
    WatchdogTlsFileSet::new(
        501,
        PathBuf::from(SERVER_CERTIFICATE_PATH),
        PathBuf::from(SERVER_PRIVATE_KEY_PATH),
        PathBuf::from(CONTROLLER_CA_PATH),
    )
    .unwrap()
}

// Creates and starts one native server from the generated identity hierarchy.
fn running_server(
    identity: &TestTlsIdentity,
    maximum_workers: usize,
    handshake_timeout_milliseconds: u64,
) -> (
    Arc<WatchdogRustlsTcpServer>,
    JoinHandle<Result<(), WatchdogError>>,
) {
    running_server_for_fingerprint(
        identity,
        maximum_workers,
        handshake_timeout_milliseconds,
        identity.controller_sha256.clone(),
    )
}

// Creates and starts one native server with a caller-selected protocol allowlist digest.
fn running_server_for_fingerprint(
    identity: &TestTlsIdentity,
    maximum_workers: usize,
    handshake_timeout_milliseconds: u64,
    allowed_fingerprint: String,
) -> (
    Arc<WatchdogRustlsTcpServer>,
    JoinHandle<Result<(), WatchdogError>>,
) {
    let (server, worker, _) = running_server_with_fingerprint(
        identity,
        maximum_workers,
        handshake_timeout_milliseconds,
        allowed_fingerprint,
    );
    (server, worker)
}

// Creates and starts one native server while returning its shared resident fanout.
fn running_server_with_fingerprint(
    identity: &TestTlsIdentity,
    maximum_workers: usize,
    handshake_timeout_milliseconds: u64,
    allowed_fingerprint: String,
) -> (
    Arc<WatchdogRustlsTcpServer>,
    JoinHandle<Result<(), WatchdogError>>,
    Arc<WatchdogLiveFanout>,
) {
    let tls = WatchdogRustlsServerConfiguration::load(
        &tls_file_set(),
        &MockTlsFileProvider::safe(identity),
    )
    .unwrap();
    let registry = Arc::new(
        WatchdogControllerRegistry::open_persistent(
            WatchdogControllerAllowlist::parse(
                format!(
                    "version=1\ninstallation_id={}\ncontroller={},{}\n",
                    "f".repeat(64),
                    CONTROLLER_ID,
                    allowed_fingerprint,
                )
                .as_bytes(),
            )
            .unwrap(),
            1,
            Arc::new(MemoryControllerSnapshots::new()),
        )
        .unwrap(),
    );
    let listener = Arc::new(WatchdogProtocolListener::new(
        Arc::new(WatchdogProtocolDispatcher::new(Arc::new(
            PingOnlyDataProvider,
        ))),
        registry,
        Arc::new(SequenceSessionProvider::new(allowed_fingerprint)),
        WatchdogProtocolListenerLimits::new(maximum_workers, 8, 500, 500).unwrap(),
    ));
    let fanout = Arc::new(WatchdogLiveFanout::new(
        WatchdogLiveFanoutLimits::production(),
    ));
    let server = Arc::new(
        WatchdogRustlsTcpServer::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            listener,
            fanout.clone(),
            tls,
            WatchdogRustlsTcpLimits::new(maximum_workers, handshake_timeout_milliseconds, 5)
                .unwrap(),
        )
        .unwrap(),
    );
    let serving = server.clone();
    let worker = thread::spawn(move || serving.serve());
    (server, worker, fanout)
}

// Connects one selected controller identity and completes its real TLS 1.3 handshake.
fn connect_controller(
    address: SocketAddr,
    identity: &TestTlsIdentity,
    certificate: &[u8],
    private_key: &[u8],
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let configuration = client_configuration(identity, certificate, private_key);
    let client = ClientConnection::new(
        configuration,
        ServerName::try_from("watchdog.local").unwrap().to_owned(),
    )
    .map_err(|_| "client TLS state is invalid".to_string())?;
    let socket = TcpStream::connect(address).map_err(|_| "client connection failed".to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .and_then(|_| socket.set_write_timeout(Some(Duration::from_secs(1))))
        .map_err(|_| "client deadlines failed".to_string())?;
    let mut connection = StreamOwned::new(client, socket);
    while connection.conn.is_handshaking() {
        connection
            .conn
            .complete_io(&mut connection.sock)
            .map_err(|_| "client handshake failed".to_string())?;
    }
    Ok(connection)
}

// Builds one TLS 1.3 client that trusts the server CA and presents the selected leaf.
fn client_configuration(
    identity: &TestTlsIdentity,
    certificate: &[u8],
    private_key: &[u8],
) -> Arc<ClientConfig> {
    let ca_certificates = rustls_pemfile::certs(&mut Cursor::new(&identity.ca_certificate))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate).unwrap();
    }
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(private_key))
        .unwrap()
        .unwrap();
    Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)
            .unwrap(),
    )
}

// Reads and decodes one complete framed protocol response from a TLS client.
fn read_response(
    client: &mut StreamOwned<ClientConnection, TcpStream>,
) -> Result<WatchdogProtocolResponse, String> {
    let mut header = [0_u8; 4];
    client
        .read_exact(&mut header)
        .map_err(|_| "response header is absent".to_string())?;
    let length = u32::from_be_bytes(header) as usize;
    let mut body = vec![0_u8; length];
    client
        .read_exact(&mut body)
        .map_err(|_| "response body is absent".to_string())?;
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    let payload = decode_watchdog_protocol_frame(&frame)
        .map_err(|_| "response frame is invalid".to_string())?;
    decode_watchdog_protocol_response(payload).map_err(|_| "response body is invalid".to_string())
}

// Encodes one complete typed request under the established protocol-v3 frame.
fn request_frame(request_id: u64, kind: WatchdogProtocolRequestKind) -> Vec<u8> {
    let request = WatchdogProtocolRequest::new(request_id, kind).unwrap();
    encode_watchdog_protocol_frame(&encode_watchdog_protocol_request(&request).unwrap()).unwrap()
}

// Returns whether one raw peer observes closure within its configured deadline.
fn connection_closed(connection: &mut TcpStream) -> bool {
    let mut byte = [0_u8; 1];
    match connection.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            false
        }
        Err(_) => true,
    }
}

// Writes one private fixture file with its final exact mode.
fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

// Creates one exact process-bound controller target for a monotonic session.
fn protected_target(generation: u64) -> WatchdogProtectedEngine {
    let process_id = u32::try_from(generation).unwrap() + 100;
    WatchdogProtectedEngine::parse(&format!(
        "version=1\ngeneration={generation:032x}\nphase=armed\ncontainer_name=container-{generation}\ncontainer_id={generation:064x}\npid={process_id}\nstart_ticks={}\nboot_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\ncgroup=/sys/fs/cgroup/letsinfer/{process_id}\n",
        generation * 10,
    ))
    .unwrap()
}

// Waits boundedly for the accepted subscription worker to register its mailbox.
fn wait_for_subscriber(fanout: &WatchdogLiveFanout) {
    for _ in 0..100 {
        if fanout.subscriber_count().unwrap() == 1 {
            return;
        }
        thread::sleep(Duration::from_millis(2));
    }
    panic!("live subscriber was not registered");
}

// Creates one complete sample on the exact resident one-second timeline.
fn protocol_sample(sequence: u64) -> WatchdogSample {
    WatchdogSample::new(sequence, sequence * 1_000, sequence * 1_000).unwrap()
}

// Encodes bytes as their canonical lowercase hexadecimal identity.
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
