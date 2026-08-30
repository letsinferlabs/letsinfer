// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flate2::write::GzEncoder;
use flate2::Compression;
use li_core_interface::Sha256Digest;
use li_core_update_manager::{
    CoreInstallation, CoreUpdateArtifactIo, CoreUpdateArtifactProvider,
    CoreUpdateCandidateFilesystem, CoreUpdateCandidateRequest, CoreUpdateCandidateWorkspace,
    CoreUpdateCommand, CoreUpdateCommandOutput, CoreUpdateCommandRunner, CoreUpdateError,
    CoreUpdateReleasePlatform, CoreUpdateReleaseTransport, CoreUpdateSignatureVerifier,
    CoreVersion, CurlCoreUpdateReleaseTransport, FilesystemCoreUpdateArtifactIo,
    FilesystemCoreUpdateArtifactProvider, FilesystemCoreUpdateCandidateFilesystem,
    GithubCoreUpdateCandidateInstaller, ProcessCoreUpdateCommandRunner,
    SshKeygenCoreUpdateSignatureVerifier,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};
use tempfile::TempDir;

const ARCHIVE_NAME: &str = "letsinfer-macos-arm64.tar.gz";
const CHECKSUM_NAME: &str = "SHA256SUMS";
const SIGNATURE_NAME: &str = "SHA256SUMS.sig";
const LIST_URL: &str =
    "https://api.github.com/repos/letsinferlabs/letsinfer/releases?per_page=100&page=1";
const PRIVATE_MODE: u32 = 0o700;
const VERSION_MODE: u32 = 0o755;
const IMMUTABLE_DIRECTORY_MODE: u32 = 0o555;
const IMMUTABLE_FILE_MODE: u32 = 0o444;
const IMMUTABLE_EXECUTABLE_MODE: u32 = 0o555;
const CORE_RELEASE_MANIFEST_NAME: &str = "li_core_release_manifest_v1.json";

// Injects deterministic release bytes and exact boundary failures without network access.
#[derive(Default)]
struct MockReleaseTransport {
    responses: Mutex<BTreeMap<String, Vec<u8>>>,
    calls: Mutex<Vec<String>>,
    failure_url: Mutex<Option<String>>,
}

impl MockReleaseTransport {
    // Adds one exact URL response to the deterministic transport.
    fn insert(&self, url: String, bytes: Vec<u8>) {
        self.responses.lock().expect("responses").insert(url, bytes);
    }

    // Schedules one stable failure at an exact URL.
    fn fail(&self, url: String) {
        *self.failure_url.lock().expect("failure URL") = Some(url);
    }

    // Returns the complete deterministic URL sequence.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}

impl CoreUpdateReleaseTransport for MockReleaseTransport {
    // Writes one configured response into the installer-created private destination.
    fn download(
        &self,
        url: &str,
        destination: &Path,
        maximum_bytes: u64,
    ) -> Result<(), CoreUpdateError> {
        self.calls.lock().expect("calls").push(url.to_string());
        if self.failure_url.lock().expect("failure URL").as_deref() == Some(url) {
            return Err(CoreUpdateError::provider(
                "release download",
                "mocked network failure",
            ));
        }
        let bytes = self
            .responses
            .lock()
            .expect("responses")
            .get(url)
            .cloned()
            .ok_or_else(|| {
                CoreUpdateError::provider("release download", "mocked response is unavailable")
            })?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(CoreUpdateError::provider(
                "release download",
                "mocked response exceeds its boundary",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(destination)
            .map_err(|_| {
                CoreUpdateError::provider("release download", "mocked destination is unavailable")
            })?;
        file.write_all(&bytes).map_err(|_| {
            CoreUpdateError::provider("release download", "mocked response could not be written")
        })?;
        file.sync_all().map_err(|_| {
            CoreUpdateError::provider("release download", "mocked response could not be persisted")
        })
    }
}

// Authenticates only the exact deterministic checksum message used by a fixture.
struct MockSignatureVerifier {
    expected_message: Mutex<Vec<u8>>,
    calls: Mutex<usize>,
    should_fail: Mutex<bool>,
}

impl MockSignatureVerifier {
    // Creates one verifier bound to the fixture checksum document.
    fn new(expected_message: Vec<u8>) -> Self {
        Self {
            expected_message: Mutex::new(expected_message),
            calls: Mutex::new(0),
            should_fail: Mutex::new(false),
        }
    }

    // Selects a deterministic authentication failure.
    fn fail(&self) {
        *self.should_fail.lock().expect("signature failure") = true;
    }

    // Returns how many signature checks reached the trust boundary.
    fn call_count(&self) -> usize {
        *self.calls.lock().expect("signature calls")
    }
}

impl CoreUpdateSignatureVerifier for MockSignatureVerifier {
    // Requires exact signed bytes and a private regular signature file.
    fn verify(&self, message: &[u8], signature: &Path) -> Result<(), CoreUpdateError> {
        *self.calls.lock().expect("signature calls") += 1;
        if *self.should_fail.lock().expect("signature failure")
            || message != self.expected_message.lock().expect("message").as_slice()
            || !signature.is_file()
        {
            return Err(CoreUpdateError::provider(
                "release signature",
                "mocked signature is invalid",
            ));
        }
        Ok(())
    }
}

// Wraps the production filesystem with one deterministic injected open failure.
struct MockCandidateFilesystem {
    production: FilesystemCoreUpdateCandidateFilesystem,
    should_fail: Mutex<bool>,
}

impl MockCandidateFilesystem {
    // Creates one filesystem mock that delegates ordinary paths to the production provider.
    fn new(owner_user_id: u32) -> Self {
        Self {
            production: FilesystemCoreUpdateCandidateFilesystem::new(owner_user_id),
            should_fail: Mutex::new(false),
        }
    }

    // Selects one deterministic workspace-open failure.
    fn fail(&self) {
        *self.should_fail.lock().expect("filesystem failure") = true;
    }
}

impl CoreUpdateCandidateFilesystem for MockCandidateFilesystem {
    // Opens the real isolated workspace unless the exact injected boundary fails.
    fn open(
        &self,
        request: &CoreUpdateCandidateRequest,
    ) -> Result<Box<dyn CoreUpdateCandidateWorkspace>, CoreUpdateError> {
        if *self.should_fail.lock().expect("filesystem failure") {
            return Err(CoreUpdateError::provider(
                "candidate filesystem",
                "mocked filesystem failure",
            ));
        }
        self.production.open(request)
    }
}

// Records exact command requests and returns one configured bounded result.
struct MockCommandRunner {
    requests: Mutex<Vec<CoreUpdateCommand>>,
    success: bool,
}

impl MockCommandRunner {
    // Creates one deterministic native command runner.
    fn new(success: bool) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            success,
        }
    }

    // Returns every captured shell-free invocation.
    fn requests(&self) -> Vec<CoreUpdateCommand> {
        self.requests.lock().expect("requests").clone()
    }
}

impl CoreUpdateCommandRunner for MockCommandRunner {
    // Captures one exact argv and returns the configured process status.
    fn run(&self, command: &CoreUpdateCommand) -> Result<CoreUpdateCommandOutput, CoreUpdateError> {
        self.requests
            .lock()
            .expect("requests")
            .push(command.clone());
        CoreUpdateCommandOutput::new(self.success, Vec::new(), Vec::new())
    }
}

// Selects one material archive contract violation for a focused failure matrix.
#[derive(Clone, Copy)]
enum ArchiveFault {
    None,
    UnsafePath,
    Symlink,
    InvalidMode,
    ManifestSize,
    ManifestChecksum,
}

// Stores exact signed release inputs and their expected native manifest identity.
struct ReleaseFixture {
    version: String,
    archive: Vec<u8>,
    checksum: Vec<u8>,
    signature: Vec<u8>,
    source_identity: Sha256Digest,
}

impl ReleaseFixture {
    // Creates one deterministic native archive and signature-bound checksum document.
    fn new(version: &str, fault: ArchiveFault) -> Self {
        Self::with_source_version(version, version, fault)
    }

    // Creates a fixture that can deliberately separate selected and manifested versions.
    fn with_source_version(version: &str, source_version: &str, fault: ArchiveFault) -> Self {
        let payloads = native_payloads(source_version);
        let files = payloads
            .iter()
            .map(|(path, bytes)| {
                let is_fault_target = path == "bin/li_node";
                json!({
                    "bytes": bytes.len() as u64
                        + u64::from(is_fault_target && matches!(fault, ArchiveFault::ManifestSize)),
                    "mode": 0o755,
                    "path": path,
                    "sha256": if is_fault_target && matches!(fault, ArchiveFault::ManifestChecksum) {
                        "0".repeat(64)
                    } else {
                        digest_text(bytes)
                    }
                })
            })
            .collect::<Vec<_>>();
        let manifest = json!({
            "schema": {"name": "li_core_release_manifest", "version": 1},
            "release": {"version": source_version},
            "platform": {"os": "macos", "architecture": "arm64"},
            "files": files
        });
        let mut manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
        manifest_bytes.push(b'\n');
        let source_identity = digest(&manifest_bytes);
        let archive = source_archive(&manifest_bytes, &payloads, fault);
        let checksum = format!("{}  {ARCHIVE_NAME}\n", digest_text(&archive)).into_bytes();
        Self {
            version: version.to_string(),
            archive,
            checksum,
            signature: b"deterministic-sshsig".to_vec(),
            source_identity,
        }
    }

    // Returns one exact GitHub release document for this fixture.
    fn release_document(&self) -> Value {
        release_document(
            &self.version,
            self.archive.len() as u64,
            self.checksum.len() as u64,
            self.signature.len() as u64,
        )
    }

    // Registers the exact selected release assets with a mocked transport.
    fn register_assets(&self, transport: &MockReleaseTransport) {
        let tag = format!("v{}", self.version);
        transport.insert(asset_url(&tag, CHECKSUM_NAME), self.checksum.clone());
        transport.insert(asset_url(&tag, SIGNATURE_NAME), self.signature.clone());
        transport.insert(asset_url(&tag, ARCHIVE_NAME), self.archive.clone());
    }
}

// Owns one complete isolated active Core and its injected candidate providers.
struct Harness {
    _temporary: TempDir,
    home: PathBuf,
    provider: Arc<FilesystemCoreUpdateArtifactProvider>,
    artifact_io: Arc<FilesystemCoreUpdateArtifactIo>,
    candidate_filesystem: Arc<MockCandidateFilesystem>,
    transport: Arc<MockReleaseTransport>,
    verifier: Arc<MockSignatureVerifier>,
    current: CoreInstallation,
    update_id: Sha256Digest,
}

impl Harness {
    // Creates one exact active Core layout and candidate installer around mocked external ports.
    fn new(current_version: &str, metadata: Vec<u8>, fixture: &ReleaseFixture) -> Self {
        let temporary = tempfile::tempdir().expect("temporary root");
        let home = temporary.path().join("home");
        let owner_user_id = unsafe { libc::geteuid() };
        let current = install_active_core(&home, current_version, owner_user_id);
        let artifact_io = Arc::new(FilesystemCoreUpdateArtifactIo::new(owner_user_id));
        let candidate_filesystem = Arc::new(MockCandidateFilesystem::new(owner_user_id));
        let transport = Arc::new(MockReleaseTransport::default());
        let metadata_url = if metadata.starts_with(b"[") {
            LIST_URL.to_string()
        } else {
            pinned_url(&fixture.version)
        };
        transport.insert(metadata_url, metadata);
        fixture.register_assets(&transport);
        let verifier = Arc::new(MockSignatureVerifier::new(fixture.checksum.clone()));
        let installer = Arc::new(GithubCoreUpdateCandidateInstaller::new(
            CoreUpdateReleasePlatform::MacosArm64,
            transport.clone(),
            verifier.clone(),
            candidate_filesystem.clone(),
        ));
        let provider = Arc::new(
            FilesystemCoreUpdateArtifactProvider::new(home.clone(), artifact_io.clone(), installer)
                .expect("artifact provider"),
        );
        Self {
            _temporary: temporary,
            home,
            provider,
            artifact_io,
            candidate_filesystem,
            transport,
            verifier,
            current,
            update_id: digest(b"update-id"),
        }
    }

    // Prepares the configured exact requested version through the production artifact boundary.
    fn prepare_requested(
        &self,
        version: &str,
    ) -> Result<li_core_update_manager::PreparedCoreUpdate, CoreUpdateError> {
        self.provider.prepare(
            &self.update_id,
            Some(&CoreVersion::parse(version).expect("version")),
            &self.current,
        )
    }

    // Prepares the highest release in the active Core release channel.
    fn prepare_latest(
        &self,
    ) -> Result<li_core_update_manager::PreparedCoreUpdate, CoreUpdateError> {
        self.provider.prepare(&self.update_id, None, &self.current)
    }

    // Returns the exact private workspace selected by the artifact provider.
    fn workspace(&self) -> PathBuf {
        self.home.join("core/staging").join(self.update_id.as_str())
    }
}

// Verifies signed preparation, immutable native identity, replay, and pointer non-mutation.
#[test]
fn prepares_and_replays_one_signed_candidate() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
    let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);

    let prepared = harness
        .prepare_requested("1.0.0-rc.2")
        .expect("candidate should prepare");
    assert_eq!(prepared.installation().version().as_str(), "1.0.0-rc.2");
    assert_eq!(
        prepared.installation().source_identity(),
        &fixture.source_identity
    );
    assert_eq!(harness.transport.calls().len(), 4);
    assert_eq!(harness.verifier.call_count(), 1);
    assert_eq!(
        file_mode(&harness.workspace().join("release")),
        PRIVATE_MODE
    );
    assert_eq!(
        file_mode(&harness.workspace().join("release/bin/li_node")),
        IMMUTABLE_EXECUTABLE_MODE
    );
    assert_eq!(
        fs::read_link(harness.home.join("core/current")).expect("current link"),
        installation_path(&harness.home, &harness.current)
    );

    let replay = harness
        .prepare_requested("1.0.0-rc.2")
        .expect("candidate should replay");
    assert_eq!(replay, prepared);
    assert_eq!(harness.transport.calls().len(), 4);
    assert_eq!(harness.verifier.call_count(), 1);
}

// Preserves the active stable or prerelease channel while choosing highest SemVer precedence.
#[test]
fn resolves_latest_release_within_the_active_channel() {
    let stable = ReleaseFixture::new("1.2.0", ArchiveFault::None);
    let prerelease = ReleaseFixture::new("1.3.0-rc.10", ArchiveFault::None);
    let older_prerelease = ReleaseFixture::new("1.3.0-rc.9", ArchiveFault::None);
    let documents = json!([
        prerelease.release_document(),
        stable.release_document(),
        older_prerelease.release_document(),
        {"tag_name": "macos-v1.0.0-build.1", "draft": false, "prerelease": false, "assets": []}
    ]);

    let stable_harness = Harness::new(
        "1.1.0",
        serde_json::to_vec(&documents).expect("metadata"),
        &stable,
    );
    let stable_prepared = stable_harness
        .prepare_latest()
        .expect("stable release should resolve");
    assert_eq!(stable_prepared.installation().version().as_str(), "1.2.0");

    let prerelease_harness = Harness::new(
        "1.3.0-rc.8",
        serde_json::to_vec(&documents).expect("metadata"),
        &prerelease,
    );
    let prerelease_prepared = prerelease_harness
        .prepare_latest()
        .expect("prerelease should resolve");
    assert_eq!(
        prerelease_prepared.installation().version().as_str(),
        "1.3.0-rc.10"
    );
}

// Rejects pinned tag, channel, asset URL, and size inconsistencies without fallback.
#[test]
fn rejects_invalid_release_resolution_contracts() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let mut cases = Vec::new();
    let mismatched = ReleaseFixture::new("1.0.0-rc.3", ArchiveFault::None);
    cases.push((
        "pinned tag",
        serde_json::to_vec(&mismatched.release_document()).expect("metadata"),
    ));
    let mut channel = fixture.release_document();
    channel["prerelease"] = json!(false);
    cases.push(("channel", serde_json::to_vec(&channel).expect("metadata")));
    let mut url = fixture.release_document();
    url["assets"][0]["browser_download_url"] = json!("https://example.com/SHA256SUMS");
    cases.push(("asset URL", serde_json::to_vec(&url).expect("metadata")));
    let mut size = fixture.release_document();
    size["assets"][2]["size"] = json!(0);
    cases.push(("asset size", serde_json::to_vec(&size).expect("metadata")));

    for (label, metadata) in cases {
        let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);
        let error = harness.prepare_requested("1.0.0-rc.2").expect_err(label);
        assert!(error.to_string().contains("release resolution"), "{label}");
        assert!(!harness.workspace().exists(), "{label}");
    }
}

// Rejects a GitHub tag that attempts to relabel otherwise valid native Core bytes.
#[test]
fn rejects_release_tag_and_signed_source_version_substitution() {
    let fixture =
        ReleaseFixture::with_source_version("1.0.0-rc.3", "1.0.0-rc.2", ArchiveFault::None);
    let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
    let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);

    let error = harness
        .prepare_requested("1.0.0-rc.3")
        .expect_err("source version substitution");

    assert!(error.to_string().contains("release archive"));
    assert!(!harness.workspace().exists());
}

// Cleans exact partial state after a failure at every external network boundary.
#[test]
fn cleans_partial_state_after_each_network_failure() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let urls = [
        pinned_url(&fixture.version),
        asset_url("v1.0.0-rc.2", CHECKSUM_NAME),
        asset_url("v1.0.0-rc.2", SIGNATURE_NAME),
        asset_url("v1.0.0-rc.2", ARCHIVE_NAME),
    ];
    for url in urls {
        let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
        let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);
        harness.transport.fail(url);
        let error = harness
            .prepare_requested("1.0.0-rc.2")
            .expect_err("network failure should fail");
        assert!(error.to_string().contains("release download"));
        assert!(!harness.workspace().exists());
    }
}

// Rejects invalid signatures before parsing or downloading the selected Core archive.
#[test]
fn rejects_invalid_release_signature_and_cleans_partial_state() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
    let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);
    harness.verifier.fail();

    let error = harness
        .prepare_requested("1.0.0-rc.2")
        .expect_err("signature should fail");
    assert!(error.to_string().contains("release signature"));
    assert_eq!(harness.transport.calls().len(), 3);
    assert!(!harness.workspace().exists());
}

// Rejects missing and mismatched signed checksum records without materializing Core.
#[test]
fn rejects_invalid_signed_checksum_contracts() {
    for checksum in [
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  another.tar.gz\n"
            .to_vec(),
        format!("{}  {ARCHIVE_NAME}\n", "0".repeat(64)).into_bytes(),
    ] {
        let mut fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
        fixture.checksum = checksum;
        let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
        let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);
        let error = harness
            .prepare_requested("1.0.0-rc.2")
            .expect_err("checksum should fail");
        assert!(error.to_string().contains("release checksum"));
        assert!(!harness.workspace().exists());
    }
}

// Rejects unsafe paths, non-files, modes, sizes, and content identities in closed archives.
#[test]
fn rejects_each_material_archive_contract_boundary() {
    for fault in [
        ArchiveFault::UnsafePath,
        ArchiveFault::Symlink,
        ArchiveFault::InvalidMode,
        ArchiveFault::ManifestSize,
        ArchiveFault::ManifestChecksum,
    ] {
        let fixture = ReleaseFixture::new("1.0.0-rc.2", fault);
        let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
        let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);
        let error = harness
            .prepare_requested("1.0.0-rc.2")
            .expect_err("archive contract should fail");
        assert!(
            error.to_string().contains("release archive")
                || error.to_string().contains("artifact filesystem"),
            "{error}"
        );
        assert!(!harness.workspace().exists());
    }
}

// Rejects declared download sizes that disagree with the exact received archive.
#[test]
fn rejects_release_asset_size_mismatch() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let mut metadata = fixture.release_document();
    metadata["assets"][2]["size"] = json!(fixture.archive.len() as u64 + 1);
    let harness = Harness::new(
        "1.0.0-rc.1",
        serde_json::to_vec(&metadata).expect("metadata"),
        &fixture,
    );

    let error = harness
        .prepare_requested("1.0.0-rc.2")
        .expect_err("size mismatch should fail");
    assert!(error.to_string().contains("release checksum"));
    assert!(!harness.workspace().exists());
}

// Fails closed at the injected candidate filesystem boundary before any network request.
#[test]
fn fails_at_the_candidate_filesystem_boundary() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
    let harness = Harness::new("1.0.0-rc.1", metadata, &fixture);
    harness.candidate_filesystem.fail();

    let error = harness
        .prepare_requested("1.0.0-rc.2")
        .expect_err("filesystem should fail");
    assert!(error.to_string().contains("candidate filesystem"));
    assert!(harness.transport.calls().is_empty());
}

// Lets one concurrent preparation win and makes the second caller replay without downloads.
#[test]
fn serializes_concurrent_candidate_preparation_into_one_winner() {
    let fixture = ReleaseFixture::new("1.0.0-rc.2", ArchiveFault::None);
    let metadata = serde_json::to_vec(&fixture.release_document()).expect("metadata");
    let harness = Arc::new(Harness::new("1.0.0-rc.1", metadata, &fixture));
    harness
        .artifact_io
        .prepare_workspace(&harness.workspace())
        .expect("workspace should be prepared");
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let harness = harness.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            harness.prepare_requested("1.0.0-rc.2")
        }));
    }
    barrier.wait();
    let first = workers
        .remove(0)
        .join()
        .expect("first thread")
        .expect("first result");
    let second = workers
        .remove(0)
        .join()
        .expect("second thread")
        .expect("second result");

    assert_eq!(first, second);
    assert_eq!(harness.transport.calls().len(), 4);
    assert_eq!(harness.verifier.call_count(), 1);
}

// Builds exact curl and ssh-keygen argv without a shell or hidden command discovery.
#[test]
fn production_native_adapters_use_closed_shell_free_argv() {
    let runner = Arc::new(MockCommandRunner::new(true));
    let transport =
        CurlCoreUpdateReleaseTransport::new(PathBuf::from("/usr/bin/curl"), runner.clone())
            .expect("curl transport");
    transport
        .download(
            LIST_URL,
            Path::new("/tmp/li_core_update_release.json"),
            4096,
        )
        .expect("curl invocation");
    let mut allowed_signers = tempfile::NamedTempFile::new().expect("allowed signers");
    allowed_signers
        .write_all(b"letsinfer-release ssh-ed25519 AAAA\n")
        .expect("allowed signers bytes");
    let mut signature = tempfile::NamedTempFile::new().expect("signature");
    signature
        .write_all(b"deterministic signature\n")
        .expect("signature bytes");
    let verifier = SshKeygenCoreUpdateSignatureVerifier::new(
        PathBuf::from("/usr/bin/ssh-keygen"),
        allowed_signers.path().to_path_buf(),
        runner.clone(),
    )
    .expect("signature verifier");
    verifier
        .verify(b"signed checksums\n", signature.path())
        .expect("signature invocation");

    let requests = runner.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].executable(), Path::new("/usr/bin/curl"));
    assert!(requests[0]
        .arguments()
        .windows(2)
        .any(|arguments| arguments == [OsString::from("--proto"), OsString::from("=https")]));
    assert!(!requests[0]
        .arguments()
        .iter()
        .any(|argument| argument == "sh" || argument == "-c"));
    assert_eq!(requests[1].executable(), Path::new("/usr/bin/ssh-keygen"));
    assert!(requests[1].arguments().windows(2).any(|arguments| {
        arguments == [OsString::from("-I"), OsString::from("letsinfer-release")]
    }));
    assert!(requests[1].arguments().windows(2).any(|arguments| {
        arguments == [OsString::from("-n"), OsString::from("letsinfer-release")]
    }));
    assert_eq!(requests[1].standard_input(), b"signed checksums\n");
}

// Proves production command execution enforces shell, time, and output bounds before return.
#[test]
fn production_command_runner_is_time_and_output_bounded() {
    assert!(CoreUpdateCommand::new(PathBuf::from("/bin/sh"), Vec::new(), Vec::new()).is_err());

    let runner = ProcessCoreUpdateCommandRunner;
    let endless = CoreUpdateCommand::new_bounded(
        PathBuf::from("/usr/bin/yes"),
        Vec::new(),
        Vec::new(),
        Duration::from_millis(20),
        128,
    )
    .expect("bounded command");
    let started = Instant::now();
    let timeout = runner.run(&endless).expect_err("deadline");
    assert!(timeout.to_string().contains("native command"));
    assert!(started.elapsed() < Duration::from_secs(2));

    let oversized = CoreUpdateCommand::new_bounded(
        PathBuf::from("/usr/bin/printf"),
        vec![OsString::from("abcdefghijklmnopqrstuvwxyz")],
        Vec::new(),
        Duration::from_secs(1),
        8,
    )
    .expect("bounded output command");
    let output = runner.run(&oversized).expect_err("output bound");
    assert!(output.to_string().contains("diagnostics"));
}

// Rejects a replaceable allowed-signers path before invoking the native verifier.
#[test]
fn production_signature_verifier_rejects_replaceable_trust() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let trust_target = temporary.path().join("trust-target");
    fs::write(&trust_target, b"letsinfer-release ssh-ed25519 AAAA\n").expect("trust bytes");
    let trust_link = temporary.path().join("trust-link");
    symlink(&trust_target, &trust_link).expect("trust symlink");
    let signature = temporary.path().join("signature");
    fs::write(&signature, b"deterministic signature\n").expect("signature bytes");
    let runner = Arc::new(MockCommandRunner::new(true));
    let verifier = SshKeygenCoreUpdateSignatureVerifier::new(
        PathBuf::from("/usr/bin/ssh-keygen"),
        trust_link,
        runner.clone(),
    )
    .expect("verifier should configure");

    let error = verifier
        .verify(b"signed checksums\n", &signature)
        .expect_err("replaceable trust should fail");
    assert!(error.to_string().contains("release signature"));
    assert!(runner.requests().is_empty());
}

// Creates one exact active immutable native Core layout for provider integration tests.
fn install_active_core(home: &Path, version: &str, owner_user_id: u32) -> CoreInstallation {
    fs::create_dir(home).expect("home");
    set_mode(home, PRIVATE_MODE);
    let core_root = home.join("core");
    fs::create_dir(&core_root).expect("core root");
    set_mode(&core_root, PRIVATE_MODE);
    let versions_root = core_root.join("versions");
    fs::create_dir(&versions_root).expect("versions root");
    set_mode(&versions_root, VERSION_MODE);
    let version_root = versions_root.join(version);
    fs::create_dir(&version_root).expect("version root");
    set_mode(&version_root, VERSION_MODE);
    let payloads = native_payloads(version);
    let files = payloads
        .iter()
        .map(|(path, bytes)| {
            json!({
                "bytes": bytes.len(),
                "mode": 0o755,
                "path": path,
                "sha256": digest_text(bytes)
            })
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "schema": {"name": "li_core_release_manifest", "version": 1},
        "release": {"version": version},
        "platform": {"os": "macos", "architecture": "arm64"},
        "files": files
    });
    let mut manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
    manifest_bytes.push(b'\n');
    let identity = digest(&manifest_bytes);
    let installation = CoreInstallation::new(
        CoreVersion::parse(version).expect("active version"),
        identity,
    );
    let root = installation_path(home, &installation);
    fs::create_dir(&root).expect("native root");
    fs::create_dir(root.join("bin")).expect("native directory");
    for (path, bytes) in payloads {
        let destination = root.join(path);
        fs::write(&destination, bytes).expect("active native file");
        set_mode(&destination, IMMUTABLE_EXECUTABLE_MODE);
    }
    fs::write(root.join(CORE_RELEASE_MANIFEST_NAME), manifest_bytes).expect("active manifest");
    set_mode(&root.join(CORE_RELEASE_MANIFEST_NAME), IMMUTABLE_FILE_MODE);
    set_mode(&root.join("bin"), IMMUTABLE_DIRECTORY_MODE);
    set_mode(&root, IMMUTABLE_DIRECTORY_MODE);
    symlink(&root, core_root.join("current")).expect("current link");
    assert_eq!(unsafe { libc::geteuid() }, owner_user_id);
    installation
}

// Returns one content-addressed Core installation path.
fn installation_path(home: &Path, installation: &CoreInstallation) -> PathBuf {
    home.join("core/versions")
        .join(installation.version().as_str())
        .join(installation.source_identity().as_str())
}

// Returns one exact GitHub pinned-release metadata URL.
fn pinned_url(version: &str) -> String {
    format!("https://api.github.com/repos/letsinferlabs/letsinfer/releases/tags/v{version}")
}

// Returns one exact official GitHub release asset URL.
fn asset_url(tag: &str, name: &str) -> String {
    format!("https://github.com/letsinferlabs/letsinfer/releases/download/{tag}/{name}")
}

// Creates one GitHub release projection with the complete selected asset set.
fn release_document(
    version: &str,
    archive_bytes: u64,
    checksum_bytes: u64,
    signature_bytes: u64,
) -> Value {
    let tag = format!("v{version}");
    json!({
        "tag_name": tag,
        "draft": false,
        "prerelease": version.contains('-'),
        "assets": [
            {
                "name": CHECKSUM_NAME,
                "browser_download_url": asset_url(&format!("v{version}"), CHECKSUM_NAME),
                "size": checksum_bytes
            },
            {
                "name": SIGNATURE_NAME,
                "browser_download_url": asset_url(&format!("v{version}"), SIGNATURE_NAME),
                "size": signature_bytes
            },
            {
                "name": ARCHIVE_NAME,
                "browser_download_url": asset_url(&format!("v{version}"), ARCHIVE_NAME),
                "size": archive_bytes
            }
        ]
    })
}

// Returns the exact macOS arm64 native binary closure in manifest order.
fn native_payloads(version: &str) -> BTreeMap<String, Vec<u8>> {
    [
        "bin/li_benchmark_worker",
        "bin/li_core_setup",
        "bin/li_gateway",
        "bin/li_hardware_macos_probe",
        "bin/li_letsinfer",
        "bin/li_node",
    ]
    .into_iter()
    .map(|path| {
        (
            path.to_string(),
            format!("native:{version}:{path}\n").into_bytes(),
        )
    })
    .collect()
}

// Builds one normalized native gzip archive with an optional exact contract fault.
fn source_archive(
    manifest: &[u8],
    payloads: &BTreeMap<String, Vec<u8>>,
    fault: ArchiveFault,
) -> Vec<u8> {
    let mut compressed = Vec::new();
    {
        let encoder = GzEncoder::new(&mut compressed, Compression::default());
        let mut archive = Builder::new(encoder);
        append_directory(&mut archive, "letsinfer", 0o755);
        if matches!(fault, ArchiveFault::UnsafePath) {
            append_file(&mut archive, "letsinfer\\escape", 0o644, b"unsafe");
        } else {
            append_directory(&mut archive, "letsinfer/bin", 0o755);
            append_file(
                &mut archive,
                &format!("letsinfer/{CORE_RELEASE_MANIFEST_NAME}"),
                0o644,
                manifest,
            );
            for (path, bytes) in payloads {
                let archive_path = format!("letsinfer/{path}");
                if path == "bin/li_node" && matches!(fault, ArchiveFault::Symlink) {
                    append_symlink(&mut archive, &archive_path, "/tmp/escape");
                } else {
                    let mode =
                        if path == "bin/li_node" && matches!(fault, ArchiveFault::InvalidMode) {
                            0o600
                        } else {
                            0o755
                        };
                    append_file(&mut archive, &archive_path, mode, bytes);
                }
            }
        }
        archive.finish().expect("archive should finish");
        archive
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");
    }
    compressed
}

// Appends one normalized directory header to a deterministic archive.
fn append_directory(archive: &mut Builder<GzEncoder<&mut Vec<u8>>>, path: &str, mode: u32) {
    let mut header = normalized_header(EntryType::Directory, mode, 0);
    header.set_path(path).expect("directory path");
    header.set_cksum();
    archive
        .append(&header, std::io::empty())
        .expect("directory should append");
}

// Appends one normalized regular file to a deterministic archive.
fn append_file(
    archive: &mut Builder<GzEncoder<&mut Vec<u8>>>,
    path: &str,
    mode: u32,
    bytes: &[u8],
) {
    let mut header = normalized_header(EntryType::Regular, mode, bytes.len() as u64);
    header.set_path(path).expect("file path");
    header.set_cksum();
    archive.append(&header, bytes).expect("file should append");
}

// Appends one forbidden symlink member for the archive type boundary.
fn append_symlink(archive: &mut Builder<GzEncoder<&mut Vec<u8>>>, path: &str, target: &str) {
    let mut header = normalized_header(EntryType::Symlink, 0o777, 0);
    header.set_path(path).expect("symlink path");
    header.set_link_name(target).expect("symlink target");
    header.set_cksum();
    archive
        .append(&header, std::io::empty())
        .expect("symlink should append");
}

// Creates one deterministic USTAR header with the release archive metadata contract.
fn normalized_header(entry_type: EntryType, mode: u32, size: u64) -> Header {
    let mut header = Header::new_ustar();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_size(size);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_username("").expect("username");
    header.set_groupname("").expect("groupname");
    header
}

// Applies one exact Unix permission mode to a fixture path.
fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode should be set");
}

// Returns the exact Unix permission bits for one fixture path.
fn file_mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

// Returns one shared lowercase SHA-256 identity for fixture bytes.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&digest_text(bytes)).expect("digest")
}

// Returns one lowercase SHA-256 string for fixture bytes.
fn digest_text(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
