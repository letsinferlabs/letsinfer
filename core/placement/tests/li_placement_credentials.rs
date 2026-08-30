// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use li_core_interface::{
    CredentialId, DeviceId, EndpointOwnership, EntityTimestamps, NodeAddress, NodeId, Placement,
    PlacementAssignment, PlacementGroupId, PlacementId, PlacementResources, PlacementState,
    PortRange, RuntimeInstallationId, TaskId, UnixMilliseconds,
};
use li_placement_manager::{
    FilesystemPlacementCredentialProvider, OpenSslPlacementTlsMaterialProvider,
    PlacementCredentialDisposition, PlacementCredentialProvider, PlacementCredentialReferences,
    PlacementError, PlacementMaterialIdentityProvider, PlacementSecretIo, PlacementSecretMaterial,
    PlacementSecretMaterialProvider, PlacementTlsMaterial, PlacementTlsMaterialProvider,
    PlacementTlsWorkspaceIo, RandomPlacementSecretMaterialProvider, ShellFreeCommand,
    ShellFreeCommandOutput, ShellFreeCommandRunner, ShellFreeEnvironmentValue,
    SystemPlacementSecretIo, SystemPlacementTlsWorkspaceIo,
};

const CREDENTIAL_FILE: &str = "li_engine_credential";
const CERTIFICATE_FILE: &str = "li_engine_tls_certificate.pem";
const PRIVATE_KEY_FILE: &str = "li_engine_tls_private_key.pem";
const METADATA_FILE: &str = "li_placement_credentials_v1.json";

// Returns one exact placement fixture.
fn placement() -> Placement {
    placement_at("node.local")
}

// Returns one exact placement fixture at a supplied TLS host identity.
fn placement_at(address: &str) -> Placement {
    Placement::new(
        PlacementId::parse(&"1".repeat(32)).expect("placement"),
        PlacementGroupId::parse(&"2".repeat(32)).expect("group"),
        PlacementAssignment::new(
            NodeId::parse(&"3".repeat(32)).expect("node"),
            RuntimeInstallationId::parse(&"4".repeat(32)).expect("installation"),
            li_core_interface::HardwareObservationId::parse(&"6".repeat(32))
                .expect("hardware observation"),
            li_core_interface::BootId::parse("11111111-2222-3333-4444-555555555555").expect("boot"),
            li_core_interface::UnixMilliseconds::new(900),
            TaskId::parse("task-0").expect("task"),
            NodeAddress::parse(address).expect("address"),
            PlacementResources::new(
                PortRange::new(18_000, 2).expect("ports"),
                vec![DeviceId::parse("GPU-A").expect("GPU")],
                None,
            )
            .expect("resources"),
            EndpointOwnership::Owner,
        ),
        PlacementState::Staging,
        None,
        None,
        EntityTimestamps::new(UnixMilliseconds::new(1_000), UnixMilliseconds::new(1_000))
            .expect("timestamps"),
    )
    .expect("placement")
}

// Returns one bounded fixture certificate.
fn certificate(character: char) -> Vec<u8> {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        character.to_string().repeat(96)
    )
    .into_bytes()
}

// Returns one bounded fixture private key.
fn private_key(character: char) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n",
        concat!("-----BEGIN PRIVATE", " KEY-----"),
        character.to_string().repeat(96),
        concat!("-----END PRIVATE", " KEY-----")
    )
    .into_bytes()
}

// Returns one complete fixture secret bundle.
fn secret_material(identity: char, authority: char, secret: &str) -> PlacementSecretMaterial {
    PlacementSecretMaterial::new(
        CredentialId::parse(&identity.to_string().repeat(32)).expect("credential ID"),
        secret.as_bytes().to_vec(),
        PlacementTlsMaterial::new(
            CredentialId::parse(&authority.to_string().repeat(32)).expect("CA ID"),
            certificate(authority),
            private_key(authority),
        )
        .expect("TLS"),
    )
    .expect("secret material")
}

// Mocks generated secret bundles and exact concurrent generation barriers.
struct MockMaterial {
    values: Mutex<VecDeque<PlacementSecretMaterial>>,
    fail: AtomicBool,
    calls: AtomicUsize,
    barrier: Option<Arc<Barrier>>,
}

impl MockMaterial {
    // Creates one deterministic generated-secret queue.
    fn new(values: Vec<PlacementSecretMaterial>) -> Self {
        Self {
            values: Mutex::new(values.into()),
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            barrier: None,
        }
    }

    // Creates one source that synchronizes exactly two concurrent generations.
    fn with_barrier(value: PlacementSecretMaterial, barrier: Arc<Barrier>) -> Self {
        Self {
            values: Mutex::new(VecDeque::from([value])),
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            barrier: Some(barrier),
        }
    }
}

impl PlacementSecretMaterialProvider for MockMaterial {
    // Returns the next secret bundle or configured generation failure.
    fn generate(&self, _placement: &Placement) -> Result<PlacementSecretMaterial, PlacementError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(barrier) = &self.barrier {
            barrier.wait();
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.values
            .lock()
            .expect("materials")
            .pop_front()
            .ok_or(PlacementError::ExecutionUnavailable)
    }
}

// Supplies deterministic unique incoming identities.
struct MockIdentity {
    values: Mutex<VecDeque<String>>,
    fail: AtomicBool,
}

impl MockIdentity {
    // Creates one deterministic incoming identity queue.
    fn new(values: &[char]) -> Self {
        Self {
            values: Mutex::new(
                values
                    .iter()
                    .map(|value| value.to_string().repeat(32))
                    .collect(),
            ),
            fail: AtomicBool::new(false),
        }
    }
}

impl PlacementMaterialIdentityProvider for MockIdentity {
    // Returns the next exact identity or configured entropy failure.
    fn identity(&self) -> Result<String, PlacementError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.values
            .lock()
            .expect("identities")
            .pop_front()
            .ok_or(PlacementError::ExecutionUnavailable)
    }
}

// Mocks private secret filesystem state and atomic directory activation.
#[derive(Default)]
struct MockIo {
    directories: Mutex<HashSet<PathBuf>>,
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    failures: Mutex<HashSet<String>>,
}

impl MockIo {
    // Configures one exact filesystem boundary to fail.
    fn fail(&self, action: &str) {
        self.failures
            .lock()
            .expect("failures")
            .insert(action.to_string());
    }

    // Returns whether one configured filesystem boundary must fail.
    fn should_fail(&self, action: &str) -> bool {
        self.failures.lock().expect("failures").contains(action)
    }

    // Inserts one exact file for corruption fixtures.
    fn insert(&self, path: PathBuf, payload: Vec<u8>) {
        if let Some(parent) = path.parent() {
            self.directories
                .lock()
                .expect("directories")
                .insert(parent.to_path_buf());
        }
        self.files.lock().expect("files").insert(path, payload);
    }

    // Returns direct files under one directory.
    fn files_under(&self, path: &Path) -> Vec<PathBuf> {
        self.files
            .lock()
            .expect("files")
            .keys()
            .filter(|candidate| candidate.parent() == Some(path))
            .cloned()
            .collect()
    }
}

impl PlacementSecretIo for MockIo {
    // Creates one deterministic private directory or configured failure.
    fn ensure_private_directory(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("ensure") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        self.directories
            .lock()
            .expect("directories")
            .insert(path.to_path_buf());
        Ok(())
    }

    // Creates one private file or configured write failure.
    fn write_private_file(
        &self,
        path: &Path,
        payload: &[u8],
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("write") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut files = self.files.lock().expect("files");
        if files.contains_key(path) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        files.insert(path.to_path_buf(), payload.to_vec());
        Ok(())
    }

    // Returns one bounded private file or configured read failure.
    fn read_private_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
        _owner_user_id: u32,
    ) -> Result<Option<Vec<u8>>, PlacementError> {
        if self.should_fail("read") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let value = self.files.lock().expect("files").get(path).cloned();
        if value
            .as_ref()
            .is_some_and(|payload| payload.len() > maximum_bytes)
        {
            return Err(PlacementError::ExecutionUnavailable);
        }
        Ok(value)
    }

    // Atomically moves one complete secret directory under one lock.
    fn rename_private_directory(
        &self,
        source: &Path,
        destination: &Path,
        _owner_user_id: u32,
    ) -> Result<(), PlacementError> {
        if self.should_fail("rename") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut directories = self.directories.lock().expect("directories");
        if !directories.contains(source) || directories.contains(destination) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut files = self.files.lock().expect("files");
        let moved = files
            .iter()
            .filter(|(path, _)| path.parent() == Some(source))
            .map(|(path, payload)| {
                (
                    destination.join(path.file_name().expect("file name")),
                    payload.clone(),
                )
            })
            .collect::<Vec<_>>();
        let previous = files
            .keys()
            .filter(|path| path.parent() == Some(source))
            .cloned()
            .collect::<Vec<_>>();
        for path in previous {
            files.remove(&path);
        }
        for (path, payload) in moved {
            files.insert(path, payload);
        }
        directories.remove(source);
        directories.insert(destination.to_path_buf());
        Ok(())
    }

    // Removes one exact directory while rejecting unknown file names.
    fn remove_secret_directory(
        &self,
        path: &Path,
        _owner_user_id: u32,
    ) -> Result<bool, PlacementError> {
        if self.should_fail("remove") {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut directories = self.directories.lock().expect("directories");
        if !directories.contains(path) {
            return Ok(false);
        }
        let files = self.files_under(path);
        if files.iter().any(|file| {
            !matches!(
                file.file_name().and_then(|value| value.to_str()),
                Some(CREDENTIAL_FILE | CERTIFICATE_FILE | PRIVATE_KEY_FILE | METADATA_FILE)
            )
        }) {
            return Err(PlacementError::ExecutionUnavailable);
        }
        let mut all = self.files.lock().expect("files");
        for file in files {
            all.remove(&file);
        }
        directories.remove(path);
        Ok(true)
    }
}

// Groups one credential provider and retained deterministic boundaries.
struct Fixture {
    provider: Arc<FilesystemPlacementCredentialProvider>,
    io: Arc<MockIo>,
    material: Arc<MockMaterial>,
    identities: Arc<MockIdentity>,
    placement: Placement,
    root: PathBuf,
}

// Creates one ordinary credential-provisioning fixture.
fn fixture() -> Fixture {
    let io = Arc::new(MockIo::default());
    let material = Arc::new(MockMaterial::new(vec![secret_material(
        '5',
        '6',
        "internal-credential-fixture-000000000000",
    )]));
    let identities = Arc::new(MockIdentity::new(&['8', '9']));
    let root = PathBuf::from("/managed/placement_secrets");
    let provider = Arc::new(
        FilesystemPlacementCredentialProvider::new(
            root.clone(),
            501,
            io.clone(),
            material.clone(),
            identities.clone(),
        )
        .expect("provider"),
    );
    Fixture {
        provider,
        io,
        material,
        identities,
        placement: placement(),
        root,
    }
}

// Returns the exact final credential directory for one fixture.
fn destination(fixture: &Fixture) -> PathBuf {
    fixture.root.join(fixture.placement.placement_id().as_str())
}

// Mocks OpenSSL process execution while writing generated files through exact argv paths.
#[derive(Default)]
struct GeneratingRunner {
    fail: AtomicBool,
    invalid: AtomicBool,
    calls: Mutex<Vec<ShellFreeCommand>>,
}

impl ShellFreeCommandRunner for GeneratingRunner {
    // Records exact OpenSSL argv and writes deterministic certificate/key outputs.
    fn run(
        &self,
        command: &ShellFreeCommand,
        _maximum_stdout_bytes: usize,
    ) -> Result<ShellFreeCommandOutput, PlacementError> {
        self.calls.lock().expect("calls").push(command.clone());
        if self.fail.load(Ordering::SeqCst) {
            return Ok(ShellFreeCommandOutput::new(1, Vec::new()));
        }
        let argument = |name: &str| -> PathBuf {
            let index = command
                .arguments()
                .iter()
                .position(|value| value == name)
                .expect("argument");
            PathBuf::from(&command.arguments()[index + 1])
        };
        let certificate_path = argument("-out");
        let private_key_path = argument("-keyout");
        if self.invalid.load(Ordering::SeqCst) {
            fs::write(&certificate_path, b"invalid").expect("certificate");
            fs::write(&private_key_path, b"invalid").expect("private key");
        } else {
            fs::write(&certificate_path, certificate('a')).expect("certificate");
            fs::write(&private_key_path, private_key('a')).expect("private key");
        }
        fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o644))
            .expect("certificate permissions");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .expect("key permissions");
        Ok(ShellFreeCommandOutput::new(0, Vec::new()))
    }
}

// Returns one Core-owned empty OpenSSL command root.
fn openssl_command() -> ShellFreeCommand {
    ShellFreeCommand::new(
        PathBuf::from("/usr/bin/openssl"),
        Vec::new(),
        Vec::new(),
        vec![
            ShellFreeEnvironmentValue::core("HOME", "/tmp").expect("home"),
            ShellFreeEnvironmentValue::core("PATH", "/usr/bin:/bin").expect("path"),
        ],
        PathBuf::from("/tmp"),
    )
    .expect("OpenSSL command")
}

// Rejects incomplete secret/reference shapes and redacts every diagnostic.
#[test]
fn credential_values_validate_and_redact_secret_material() {
    assert!(PlacementTlsMaterial::new(
        CredentialId::parse(&"6".repeat(32)).expect("CA"),
        b"invalid".to_vec(),
        private_key('6'),
    )
    .is_err());
    assert!(PlacementCredentialReferences::new(
        PlacementId::parse(&"1".repeat(32)).expect("placement"),
        CredentialId::parse(&"5".repeat(32)).expect("credential"),
        CredentialId::parse(&"5".repeat(32)).expect("duplicate"),
        PathBuf::from("relative"),
        PathBuf::from("/cert"),
        PathBuf::from("/key"),
        li_core_interface::Sha256Digest::parse(&"7".repeat(64)).expect("digest"),
        li_core_interface::Sha256Digest::parse(&"8".repeat(64)).expect("bundle"),
    )
    .is_err());
    let material = secret_material('5', '6', "internal-credential-fixture-000000000000");
    let debug = format!("{material:?}");
    assert!(!debug.contains("internal-credential"));
    assert!(!debug.contains(concat!("BEGIN PRIVATE", " KEY")));
    assert!(debug.contains("[redacted]"));
}

// Provisions, reconstructs, and replays reference-only credentials after restart.
#[test]
fn credential_provider_round_trips_and_replays_without_exposing_secrets() {
    let fixture = fixture();
    let created = fixture
        .provider
        .provision(&fixture.placement)
        .expect("provision");
    assert_eq!(
        created.disposition(),
        PlacementCredentialDisposition::Created
    );
    assert_eq!(
        created.references().credential_id().as_str(),
        "5".repeat(32)
    );
    let observed = fixture
        .provider
        .existing(&fixture.placement)
        .expect("existing")
        .expect("references");
    assert_eq!(&observed, created.references());
    let replay = fixture
        .provider
        .provision(&fixture.placement)
        .expect("replay");
    assert_eq!(
        replay.disposition(),
        PlacementCredentialDisposition::Existing
    );
    assert_eq!(replay.references(), created.references());
    assert_eq!(fixture.material.calls.load(Ordering::SeqCst), 1);
    let metadata = fixture
        .io
        .files
        .lock()
        .expect("files")
        .get(&destination(&fixture).join(METADATA_FILE))
        .expect("metadata")
        .clone();
    let metadata = String::from_utf8(metadata).expect("UTF-8");
    assert!(!metadata.contains("internal-credential"));
    assert!(!metadata.contains(concat!("PRIVATE", " KEY")));
}

// Rejects credential, certificate, private-key, metadata, and partial-record corruption.
#[test]
fn credential_provider_fails_closed_on_every_corruption_shape() {
    for file in [
        CREDENTIAL_FILE,
        CERTIFICATE_FILE,
        PRIVATE_KEY_FILE,
        METADATA_FILE,
        "partial",
    ] {
        let fixture = fixture();
        fixture
            .provider
            .provision(&fixture.placement)
            .expect("provision");
        let root = destination(&fixture);
        if file == "partial" {
            fixture
                .io
                .files
                .lock()
                .expect("files")
                .remove(&root.join(PRIVATE_KEY_FILE));
        } else {
            fixture.io.insert(root.join(file), b"changed".to_vec());
        }
        assert!(
            fixture.provider.existing(&fixture.placement).is_err(),
            "{file}"
        );
    }
}

// Cleans partial secret bytes after generation, identity, write, read, or rename failure.
#[test]
fn credential_provision_rolls_back_every_external_failure() {
    for boundary in ["material", "identity", "ensure", "write", "read", "rename"] {
        let fixture = fixture();
        match boundary {
            "material" => fixture.material.fail.store(true, Ordering::SeqCst),
            "identity" => fixture.identities.fail.store(true, Ordering::SeqCst),
            value => fixture.io.fail(value),
        }
        assert!(
            fixture.provider.provision(&fixture.placement).is_err(),
            "{boundary}"
        );
        assert!(!fixture
            .io
            .directories
            .lock()
            .expect("directories")
            .iter()
            .any(|path| path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.contains(".incoming."))));
    }
}

// Allows exactly one concurrent creator and returns the same winner to the loser.
#[test]
fn credential_provision_resolves_concurrent_random_material_race() {
    let placement = placement();
    let root = PathBuf::from("/managed/placement_secrets");
    let io = Arc::new(MockIo::default());
    let barrier = Arc::new(Barrier::new(2));
    let first = Arc::new(
        FilesystemPlacementCredentialProvider::new(
            root.clone(),
            501,
            io.clone(),
            Arc::new(MockMaterial::with_barrier(
                secret_material('5', '6', "first-internal-credential-000000000000"),
                barrier.clone(),
            )),
            Arc::new(MockIdentity::new(&['8'])),
        )
        .expect("first"),
    );
    let second = Arc::new(
        FilesystemPlacementCredentialProvider::new(
            root,
            501,
            io,
            Arc::new(MockMaterial::with_barrier(
                secret_material('7', '8', "second-internal-credential-00000000000"),
                barrier,
            )),
            Arc::new(MockIdentity::new(&['9'])),
        )
        .expect("second"),
    );
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first = scope.spawn(|| first.provision(&placement));
        let second = scope.spawn(|| second.provision(&placement));
        (
            first
                .join()
                .expect("first thread")
                .expect("first provision"),
            second
                .join()
                .expect("second thread")
                .expect("second provision"),
        )
    });
    assert_eq!(first_result.references(), second_result.references());
    assert_eq!(
        usize::from(first_result.disposition() == PlacementCredentialDisposition::Created)
            + usize::from(second_result.disposition() == PlacementCredentialDisposition::Created),
        1
    );
}

// Removes only exact matching references and rejects stale or unknown contents.
#[test]
fn credential_removal_is_exact_idempotent_and_fail_closed() {
    let completed = fixture();
    let provision = completed
        .provider
        .provision(&completed.placement)
        .expect("provision");
    let mut changed = provision.references().clone();
    changed = PlacementCredentialReferences::new(
        changed.placement_id().clone(),
        CredentialId::parse(&"7".repeat(32)).expect("changed"),
        changed.ca_credential_id().clone(),
        changed.engine_credential_file().to_path_buf(),
        changed.tls_certificate_file().to_path_buf(),
        changed.tls_private_key_file().to_path_buf(),
        changed.tls_certificate_sha256().clone(),
        changed.credential_bundle_sha256().clone(),
    )
    .expect("changed references");
    assert_eq!(
        completed
            .provider
            .remove_if_matches(&completed.placement, &changed)
            .expect_err("stale references"),
        PlacementError::StoreConflict
    );
    assert!(completed
        .provider
        .remove_if_matches(&completed.placement, provision.references())
        .expect("remove"));
    assert!(!completed
        .provider
        .remove_if_matches(&completed.placement, provision.references())
        .expect("replayed remove"));

    let unsafe_fixture = fixture();
    let provision = unsafe_fixture
        .provider
        .provision(&unsafe_fixture.placement)
        .expect("provision");
    unsafe_fixture.io.insert(
        destination(&unsafe_fixture).join("foreign"),
        b"data".to_vec(),
    );
    assert!(unsafe_fixture
        .provider
        .remove_if_matches(&unsafe_fixture.placement, provision.references())
        .is_err());
}

// Random secret provider uses independent CSPRNG identity and injected TLS material.
#[test]
fn random_secret_provider_generates_distinct_redacted_credentials() {
    struct MockTls(AtomicUsize);
    impl PlacementTlsMaterialProvider for MockTls {
        // Returns one deterministic TLS pair with a changing CA identity.
        fn generate(&self, _placement: &Placement) -> Result<PlacementTlsMaterial, PlacementError> {
            let value = self.0.fetch_add(1, Ordering::SeqCst) + 10;
            let character = char::from_digit((value % 6 + 10) as u32, 16).expect("hex");
            PlacementTlsMaterial::new(
                CredentialId::parse(&character.to_string().repeat(32)).expect("CA"),
                certificate(character),
                private_key(character),
            )
        }
    }
    let provider =
        RandomPlacementSecretMaterialProvider::new(Arc::new(MockTls(AtomicUsize::new(0))));
    let first = provider.generate(&placement()).expect("first");
    let second = provider.generate(&placement()).expect("second");
    assert_ne!(format!("{first:?}"), format!("{second:?}"));
    assert!(!format!("{first:?}").contains("li_internal_"));
}

// OpenSSL generator uses fixed shell-free argv and exact DNS/IP SAN identity.
#[test]
fn openssl_tls_generator_builds_exact_dns_and_ip_subjects() {
    for (host, expected_san) in [
        ("node.local", "DNS:node.local"),
        ("192.0.2.10", "IP:192.0.2.10"),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let owner = fs::metadata(directory.path()).expect("metadata").uid();
        let root = directory.path().join("placement_tls_staging");
        let runner = Arc::new(GeneratingRunner::default());
        let provider = OpenSslPlacementTlsMaterialProvider::new(
            openssl_command(),
            root.clone(),
            owner,
            runner.clone(),
            Arc::new(SystemPlacementTlsWorkspaceIo),
            Arc::new(MockIdentity::new(&['8'])),
        )
        .expect("provider");
        let material = provider.generate(&placement_at(host)).expect("TLS");
        assert!(!format!("{material:?}").contains(concat!("BEGIN PRIVATE", " KEY")));
        let calls = runner.calls.lock().expect("calls");
        let arguments = calls[0].arguments();
        assert!(arguments
            .iter()
            .any(|value| value == &format!("/CN={host}")));
        assert!(arguments.iter().any(|value| {
            value == &format!("subjectAltName={expected_san},DNS:localhost,IP:127.0.0.1")
        }));
        assert!(fs::read_dir(&root)
            .expect("workspace root")
            .next()
            .is_none());
    }
}

// OpenSSL generator cleans its private workspace after command and PEM validation failure.
#[test]
fn openssl_tls_generator_rolls_back_every_failure() {
    for boundary in ["command", "pem", "identity"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let owner = fs::metadata(directory.path()).expect("metadata").uid();
        let root = directory.path().join("placement_tls_staging");
        let runner = Arc::new(GeneratingRunner::default());
        let identities = Arc::new(MockIdentity::new(&['8']));
        match boundary {
            "command" => runner.fail.store(true, Ordering::SeqCst),
            "pem" => runner.invalid.store(true, Ordering::SeqCst),
            _ => identities.fail.store(true, Ordering::SeqCst),
        }
        let provider = OpenSslPlacementTlsMaterialProvider::new(
            openssl_command(),
            root.clone(),
            owner,
            runner,
            Arc::new(SystemPlacementTlsWorkspaceIo),
            identities,
        )
        .expect("provider");
        assert!(provider.generate(&placement()).is_err(), "{boundary}");
        if root.exists() {
            assert!(fs::read_dir(root).expect("workspace root").next().is_none());
        }
    }
}

// OpenSSL generator rejects foreign executable, environment, root, and hostname configuration.
#[test]
fn openssl_tls_generator_rejects_unsafe_configuration_and_host() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    assert!(OpenSslPlacementTlsMaterialProvider::new(
        ShellFreeCommand::new(
            PathBuf::from("/usr/bin/printf"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PathBuf::from("/tmp"),
        )
        .expect("command"),
        directory.path().join("placement_tls_staging"),
        owner,
        Arc::new(GeneratingRunner::default()),
        Arc::new(SystemPlacementTlsWorkspaceIo),
        Arc::new(MockIdentity::new(&['8'])),
    )
    .is_err());
    let provider = OpenSslPlacementTlsMaterialProvider::new(
        openssl_command(),
        directory.path().join("placement_tls_staging"),
        owner,
        Arc::new(GeneratingRunner::default()),
        Arc::new(SystemPlacementTlsWorkspaceIo),
        Arc::new(MockIdentity::new(&['8'])),
    )
    .expect("provider");
    assert!(provider.generate(&placement_at("unsafe:host")).is_err());
}

// System TLS workspace I/O enforces modes, no-follow reads, and exact cleanup names.
#[test]
fn system_tls_workspace_io_enforces_private_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    let root = directory.path().join("placement_tls_staging");
    let workspace = root.join("workspace");
    let io = SystemPlacementTlsWorkspaceIo;
    io.ensure_private_directory(&root, owner).expect("root");
    io.ensure_private_directory(&workspace, owner)
        .expect("workspace");
    let certificate_path = workspace.join("li_generated_certificate.pem");
    let key_path = workspace.join("li_generated_private_key.pem");
    fs::write(&certificate_path, certificate('a')).expect("certificate");
    fs::write(&key_path, private_key('a')).expect("key");
    fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o644)).expect("permissions");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("permissions");
    assert!(io
        .read_generated_file(&certificate_path, 16 * 1024, owner, false)
        .is_ok());
    assert!(io
        .read_generated_file(&key_path, 64 * 1024, owner, true)
        .is_ok());
    let link = workspace.join("link");
    std::os::unix::fs::symlink(&key_path, &link).expect("symlink");
    assert!(io.read_generated_file(&link, 1024, owner, true).is_err());
    fs::remove_file(link).expect("remove link");
    fs::write(workspace.join("foreign"), b"data").expect("foreign");
    assert!(io.remove_workspace(&workspace, owner).is_err());
    fs::remove_file(workspace.join("foreign")).expect("remove foreign");
    io.remove_workspace(&workspace, owner).expect("cleanup");
}

// System secret I/O enforces private modes, no-follow files, exact sets, and partial rollback.
#[test]
fn system_secret_io_enforces_private_filesystem_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("metadata").uid();
    let root = directory.path().join("placement_secrets");
    let incoming = root.join(format!(".{}.incoming.{}", "1".repeat(32), "8".repeat(32)));
    let destination = root.join("1".repeat(32));
    let io = SystemPlacementSecretIo;
    io.ensure_private_directory(&root, owner).expect("root");
    io.ensure_private_directory(&incoming, owner)
        .expect("incoming");
    for (name, payload) in [
        (
            CREDENTIAL_FILE,
            b"internal-credential-fixture-000000000000".to_vec(),
        ),
        (CERTIFICATE_FILE, certificate('6')),
        (PRIVATE_KEY_FILE, private_key('6')),
        (METADATA_FILE, b"{}\n".to_vec()),
    ] {
        io.write_private_file(&incoming.join(name), &payload, owner)
            .expect("write");
    }
    io.rename_private_directory(&incoming, &destination, owner)
        .expect("rename");
    for name in [
        CREDENTIAL_FILE,
        CERTIFICATE_FILE,
        PRIVATE_KEY_FILE,
        METADATA_FILE,
    ] {
        assert_eq!(
            fs::metadata(destination.join(name))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let link = destination.join("link");
    std::os::unix::fs::symlink(destination.join(CREDENTIAL_FILE), &link).expect("symlink");
    assert!(io.read_private_file(&link, 64, owner).is_err());
    fs::remove_file(link).expect("remove link");
    fs::write(destination.join("foreign"), b"data").expect("foreign");
    fs::set_permissions(
        destination.join("foreign"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("permissions");
    assert!(io.remove_secret_directory(&destination, owner).is_err());
    fs::remove_file(destination.join("foreign")).expect("remove foreign");
    assert!(io
        .remove_secret_directory(&destination, owner)
        .expect("remove"));

    let partial = root.join("partial");
    io.ensure_private_directory(&partial, owner)
        .expect("partial");
    io.write_private_file(&partial.join(CREDENTIAL_FILE), b"partial", owner)
        .expect("partial file");
    assert!(io
        .remove_secret_directory(&partial, owner)
        .expect("partial cleanup"));
}
