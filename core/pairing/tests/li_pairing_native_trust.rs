// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    DisplayName, InstallationId, MachineId, NodeAddress, NodeId, NodeIdentity, NodeRole,
    Sha256Digest, UnixMilliseconds,
};
use li_pairing_manager::{
    OpenSslPairingTrustProvider, PairingCandidate, PairingContext, PairingError,
    PairingMaterialProvider, PairingMembershipState, PairingNativeCommand,
    PairingNativeCommandOutput, PairingNativeCommandRunner, PairingNativeProcess,
    PairingTrustIdentityFiles, PairingTrustProvider, PairingTrustWorkspaceIo,
    SystemPairingTrustWorkspaceIo,
};
use sha2::{Digest, Sha256};

// Supplies deterministic workspace and certificate serial bytes.
struct MockMaterial(AtomicU8);

impl MockMaterial {
    // Creates deterministic material beginning at one byte value.
    fn new(value: u8) -> Self {
        Self(AtomicU8::new(value))
    }
}

impl PairingMaterialProvider for MockMaterial {
    // Fills one destination with the next deterministic byte.
    fn fill(&self, destination: &mut [u8]) -> Result<(), PairingError> {
        destination.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

// Emulates exact OpenSSL file outputs while retaining every argv for assertions.
struct MockOpenSslRunner {
    calls: Mutex<Vec<PairingNativeCommand>>,
    enrollment_transcript: Mutex<Option<Vec<u8>>>,
    membership_transcript: Mutex<Option<Vec<u8>>>,
    failed_operation: Mutex<Option<&'static str>>,
    invalid_candidate_der: AtomicBool,
    invalid_control_der: AtomicBool,
    mismatched_member_key: AtomicBool,
    invalid_member_uri: AtomicBool,
    invalid_member_validity: AtomicBool,
}

impl Default for MockOpenSslRunner {
    // Creates one successful deterministic OpenSSL boundary.
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            enrollment_transcript: Mutex::new(None),
            membership_transcript: Mutex::new(None),
            failed_operation: Mutex::new(None),
            invalid_candidate_der: AtomicBool::new(false),
            invalid_control_der: AtomicBool::new(false),
            mismatched_member_key: AtomicBool::new(false),
            invalid_member_uri: AtomicBool::new(false),
            invalid_member_validity: AtomicBool::new(false),
        }
    }
}

impl PairingNativeCommandRunner for MockOpenSslRunner {
    // Materializes deterministic command outputs from exact direct argv.
    fn run(
        &self,
        command: &PairingNativeCommand,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError> {
        assert_eq!(command.executable(), Path::new("/usr/bin/openssl"));
        assert_eq!(timeout, Duration::from_secs(15));
        assert_eq!(maximum_output_bytes, 8 * 1024);
        let arguments = command.arguments();
        let operation = command_operation(arguments);
        self.calls.lock().expect("calls").push(command.clone());
        if self
            .failed_operation
            .lock()
            .expect("failure")
            .is_some_and(|value| value == operation)
        {
            return Ok(PairingNativeCommandOutput::new(
                1,
                Vec::new(),
                b"secret candidate proof and /private/key/path".to_vec(),
                false,
            ));
        }

        let mut stdout = Vec::new();
        match operation {
            "candidate-key" => {
                let der = if self.invalid_candidate_der.load(Ordering::SeqCst) {
                    b"not-p256".to_vec()
                } else {
                    candidate_spki()
                };
                write_output(arguments, &der);
            }
            "site-public" | "site-private" | "ca-public" => {
                write_output(arguments, &site_spki());
            }
            "certificate-public" => {
                let path = output_path(arguments);
                fs::write(path, public_key_pem()).expect("certificate public PEM");
            }
            "certificate-public-der" => {
                let der = if self.mismatched_member_key.load(Ordering::SeqCst) {
                    site_spki()
                } else {
                    candidate_spki()
                };
                write_output(arguments, &der);
            }
            "ca-public-pem" => {
                let path = output_path(arguments);
                fs::write(path, site_public_key_pem()).expect("CA public PEM");
            }
            "ca-certificate-der" => write_output(arguments, b"ca-certificate-der"),
            "local-certificate-der" => write_output(
                arguments,
                if self.invalid_control_der.load(Ordering::SeqCst) {
                    b"different-local-certificate-der"
                } else {
                    b"local-certificate-der"
                },
            ),
            "member-certificate-der" => write_output(arguments, b"member-certificate-der"),
            "issue-certificate" => {
                fs::write(output_path(arguments), certificate_pem("member"))
                    .expect("member certificate");
            }
            "member-uri" => {
                stdout = if self.invalid_member_uri.load(Ordering::SeqCst) {
                    b"X509v3 Subject Alternative Name:\n    URI:urn:letsinfer:node:wrong\n".to_vec()
                } else {
                    format!(
                        "X509v3 Subject Alternative Name:\n    URI:urn:letsinfer:node:{}\n",
                        "6".repeat(32)
                    )
                    .into_bytes()
                };
            }
            "member-validity" => {
                stdout = if self.invalid_member_validity.load(Ordering::SeqCst) {
                    b"notBefore=not-a-date\nnotAfter=Jan  1 00:00:01 2126 GMT\n".to_vec()
                } else {
                    b"notBefore=Jan  1 00:00:01 2026 GMT\nnotAfter=Jan  1 00:00:01 2126 GMT\n"
                        .to_vec()
                };
            }
            "verify-proof" => {
                assert_eq!(
                    fs::read(option_path(arguments, "-signature")).expect("proof signature"),
                    b"proof-signature"
                );
                let transcript = fs::read(arguments.last().expect("transcript path"))
                    .expect("enrollment transcript");
                *self
                    .enrollment_transcript
                    .lock()
                    .expect("enrollment transcript") = Some(transcript);
            }
            "sign-membership" => {
                let transcript = fs::read(arguments.last().expect("membership path"))
                    .expect("membership transcript");
                *self
                    .membership_transcript
                    .lock()
                    .expect("membership transcript") = Some(transcript);
                write_output(arguments, b"membership-signature");
            }
            "verify-certificate" | "check-certificate" => {}
            other => panic!("unexpected OpenSSL operation: {other}: {arguments:?}"),
        }
        Ok(PairingNativeCommandOutput::new(
            0,
            stdout,
            Vec::new(),
            false,
        ))
    }

    // Rejects the long-running process path unused by trust operations.
    fn spawn(
        &self,
        _command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError> {
        Err(PairingError::TrustUnavailable)
    }
}

// Holds one complete provider fixture and its observable boundaries.
struct Fixture {
    _directory: tempfile::TempDir,
    workspace_root: PathBuf,
    provider: OpenSslPairingTrustProvider,
    runner: Arc<MockOpenSslRunner>,
    context: PairingContext,
    candidate: PairingCandidate,
}

// Creates one deterministic private trust fixture.
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("owner").uid();
    let identity_root = directory.path().join("identity");
    fs::create_dir(&identity_root).expect("identity root");
    fs::set_permissions(&identity_root, fs::Permissions::from_mode(0o700))
        .expect("identity root mode");
    let site_private_key = identity_root.join("site.key");
    let site_public_key = identity_root.join("site.pub");
    let site_ca_certificate = identity_root.join("site-ca.crt");
    let local_control_certificate = identity_root.join("local.crt");
    for (path, payload) in [
        (&site_private_key, private_key_pem()),
        (&site_public_key, site_public_key_pem()),
        (&site_ca_certificate, certificate_pem("ca")),
        (&local_control_certificate, certificate_pem("local")),
    ] {
        fs::write(path, payload).expect("identity file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("identity mode");
    }
    let identity_files = PairingTrustIdentityFiles::new(
        site_private_key,
        site_public_key,
        site_ca_certificate,
        local_control_certificate,
    )
    .expect("identity files");
    let workspace_root = directory.path().join("pairing_trust_staging");
    let runner = Arc::new(MockOpenSslRunner::default());
    let context = context();
    let candidate = candidate();
    let provider = OpenSslPairingTrustProvider::new(
        PathBuf::from("/usr/bin/openssl"),
        identity_files,
        workspace_root.clone(),
        owner,
        runner.clone(),
        Arc::new(SystemPairingTrustWorkspaceIo),
        Arc::new(MockMaterial::new(1)),
    )
    .expect("provider");
    Fixture {
        _directory: directory,
        workspace_root,
        provider,
        runner,
        context,
        candidate,
    }
}

// Returns one canonical main-node trust context bound to fixture DER identities.
fn context() -> PairingContext {
    PairingContext::new(
        NodeIdentity::new(
            NodeId::parse(&"1".repeat(32)).expect("main node"),
            MachineId::parse(&"2".repeat(32)).expect("main machine"),
            InstallationId::parse(&"3".repeat(64)).expect("main installation"),
        ),
        NodeRole::Main,
        DisplayName::parse("Home AI").expect("main name"),
        NodeAddress::parse("homeai.local").expect("main address"),
        9_770,
        digest(&site_spki()),
        digest(b"local-certificate-der"),
    )
}

// Returns one canonical child candidate using fixture P-256 public bytes.
fn candidate() -> PairingCandidate {
    PairingCandidate::new(
        NodeIdentity::new(
            NodeId::parse(&"6".repeat(32)).expect("child node"),
            MachineId::parse(&"7".repeat(32)).expect("child machine"),
            InstallationId::parse(&"8".repeat(64)).expect("child installation"),
        ),
        DisplayName::parse("Child AI").expect("child name"),
        NodeAddress::parse("child.local").expect("child address"),
        public_key_pem(),
        UnixMilliseconds::new(900),
        b"proof-signature".to_vec(),
        Some("12345678".to_string()),
        NodeAddress::parse("192.168.1.20").expect("peer"),
    )
    .expect("candidate")
}

// Verifies exact proof bytes and issues certificate and membership identities once.
#[test]
fn openssl_trust_verifies_and_issues_exact_bound_credentials() {
    let fixture = fixture();
    let transcript = b"exact-enrollment-transcript-v1";
    let fingerprint = fixture
        .provider
        .verify_candidate(
            fixture.candidate.public_key(),
            transcript,
            fixture.candidate.proof_signature(),
        )
        .expect("candidate proof");
    assert_eq!(fingerprint, digest(&candidate_spki()));
    assert_eq!(
        fixture
            .runner
            .enrollment_transcript
            .lock()
            .expect("enrollment transcript")
            .as_deref(),
        Some(transcript.as_slice())
    );

    let credentials = fixture
        .provider
        .issue_membership(
            &fixture.context,
            &fixture.candidate,
            &fingerprint,
            PairingMembershipState::Active,
            None,
        )
        .expect("membership");
    assert_eq!(credentials.site_public_key(), site_public_key_pem());
    assert_eq!(credentials.site_ca_certificate(), certificate_pem("ca"));
    assert_eq!(credentials.member_certificate(), certificate_pem("member"));
    assert_eq!(credentials.membership_signature(), b"membership-signature");
    assert_eq!(
        credentials.member_leaf_sha256(),
        &digest(b"member-certificate-der")
    );
    assert!(credentials.member_expires_at() > credentials.member_valid_from());
    let membership = fixture
        .runner
        .membership_transcript
        .lock()
        .expect("membership transcript")
        .clone()
        .expect("signed membership");
    assert!(contains(&membership, fingerprint.as_str().as_bytes()));
    assert!(contains(
        &membership,
        digest(b"member-certificate-der").as_str().as_bytes()
    ));
    assert!(contains(&membership, b"active"));
    assert!(fs::read_dir(&fixture.workspace_root)
        .expect("workspace root")
        .next()
        .is_none());
    let calls = fixture.runner.calls.lock().expect("calls");
    assert!(calls.iter().any(|command| {
        command.arguments().first().map(String::as_str) == Some("dgst")
            && command.arguments().iter().any(|value| value == "-verify")
    }));
    assert!(calls.iter().any(|command| {
        command.arguments().first().map(String::as_str) == Some("x509")
            && command
                .arguments()
                .iter()
                .any(|value| value == "-force_pubkey")
            && command
                .arguments()
                .iter()
                .any(|value| value == "-set_serial")
    }));
}

// Rejects invalid proof, non-P-256 key output, and caller-supplied fingerprint mismatch.
#[test]
fn openssl_trust_rejects_invalid_proof_key_and_fingerprint() {
    let fixture = fixture();
    *fixture.runner.failed_operation.lock().expect("failure") = Some("verify-proof");
    assert_eq!(
        fixture
            .provider
            .verify_candidate(
                fixture.candidate.public_key(),
                b"transcript",
                fixture.candidate.proof_signature(),
            )
            .expect_err("proof must fail"),
        PairingError::TrustUnavailable
    );
    *fixture.runner.failed_operation.lock().expect("failure") = None;
    fixture
        .runner
        .invalid_candidate_der
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .verify_candidate(
                fixture.candidate.public_key(),
                b"transcript",
                fixture.candidate.proof_signature(),
            )
            .expect_err("curve must fail"),
        PairingError::TrustUnavailable
    );
    fixture
        .runner
        .invalid_candidate_der
        .store(false, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .issue_membership(
                &fixture.context,
                &fixture.candidate,
                &Sha256Digest::parse(&"f".repeat(64)).expect("wrong fingerprint"),
                PairingMembershipState::Active,
                None,
            )
            .expect_err("fingerprint must fail"),
        PairingError::TrustUnavailable
    );
    fixture
        .runner
        .invalid_control_der
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .issue_membership(
                &fixture.context,
                &fixture.candidate,
                &digest(&candidate_spki()),
                PairingMembershipState::Active,
                None,
            )
            .expect_err("control certificate fingerprint must fail"),
        PairingError::TrustUnavailable
    );
    fixture
        .runner
        .invalid_control_der
        .store(false, Ordering::SeqCst);
    fixture
        .runner
        .mismatched_member_key
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .issue_membership(
                &fixture.context,
                &fixture.candidate,
                &digest(&candidate_spki()),
                PairingMembershipState::Active,
                None,
            )
            .expect_err("issued certificate key must fail"),
        PairingError::TrustUnavailable
    );
    fixture
        .runner
        .mismatched_member_key
        .store(false, Ordering::SeqCst);
    fixture
        .runner
        .invalid_member_uri
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .issue_membership(
                &fixture.context,
                &fixture.candidate,
                &digest(&candidate_spki()),
                PairingMembershipState::Active,
                None,
            )
            .expect_err("issued certificate URI must fail"),
        PairingError::TrustUnavailable
    );
    fixture
        .runner
        .invalid_member_uri
        .store(false, Ordering::SeqCst);
    fixture
        .runner
        .invalid_member_validity
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .issue_membership(
                &fixture.context,
                &fixture.candidate,
                &digest(&candidate_spki()),
                PairingMembershipState::Active,
                None,
            )
            .expect_err("issued certificate validity must fail"),
        PairingError::TrustUnavailable
    );
    assert!(fs::read_dir(&fixture.workspace_root)
        .expect("workspace root")
        .next()
        .is_none());
}

// Redacts native failure output and removes every partially issued trust file.
#[test]
fn openssl_trust_redacts_command_failure_and_cleans_workspace() {
    let fixture = fixture();
    *fixture.runner.failed_operation.lock().expect("failure") = Some("issue-certificate");
    let error = fixture
        .provider
        .issue_membership(
            &fixture.context,
            &fixture.candidate,
            &digest(&candidate_spki()),
            PairingMembershipState::PendingApproval,
            Some(UnixMilliseconds::new(1_800)),
        )
        .expect_err("issuance must fail");
    assert_eq!(error, PairingError::TrustUnavailable);
    assert_eq!(error.to_string(), "pairing trust operation failed");
    assert!(!format!("{error:?}").contains("secret"));
    assert!(!error.to_string().contains("/private/key/path"));
    assert!(fs::read_dir(&fixture.workspace_root)
        .expect("workspace root")
        .next()
        .is_none());
}

// Rejects unsafe native configuration and private identity file capabilities.
#[test]
fn openssl_trust_rejects_unsafe_configuration_and_identity_files() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("owner").uid();
    let absolute = |name: &str| directory.path().join(name);
    assert!(PairingTrustIdentityFiles::new(
        PathBuf::from("relative.key"),
        absolute("site.pub"),
        absolute("site-ca.crt"),
        absolute("local.crt"),
    )
    .is_err());
    let repeated = absolute("same");
    assert!(PairingTrustIdentityFiles::new(
        repeated.clone(),
        repeated,
        absolute("site-ca.crt"),
        absolute("local.crt"),
    )
    .is_err());
    let identities = PairingTrustIdentityFiles::new(
        absolute("site.key"),
        absolute("site.pub"),
        absolute("site-ca.crt"),
        absolute("local.crt"),
    )
    .expect("identity paths");
    assert!(OpenSslPairingTrustProvider::new(
        PathBuf::from("/usr/bin/printf"),
        identities.clone(),
        absolute("pairing_trust_staging"),
        owner,
        Arc::new(MockOpenSslRunner::default()),
        Arc::new(SystemPairingTrustWorkspaceIo),
        Arc::new(MockMaterial::new(1)),
    )
    .is_err());
    assert!(OpenSslPairingTrustProvider::new(
        PathBuf::from("/usr/bin/openssl"),
        identities,
        absolute("unsafe_workspace"),
        owner,
        Arc::new(MockOpenSslRunner::default()),
        Arc::new(SystemPairingTrustWorkspaceIo),
        Arc::new(MockMaterial::new(1)),
    )
    .is_err());

    let io = SystemPairingTrustWorkspaceIo;
    let root = absolute("pairing_trust_staging");
    let workspace = root.join("workspace");
    io.ensure_private_root(&root, owner).expect("root");
    io.create_private_workspace(&workspace, owner)
        .expect("workspace");
    let key = workspace.join("li_site_private_key.pem");
    fs::write(&key, private_key_pem()).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
    assert!(io.read_private_file(&key, 16 * 1024, owner).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("private mode");
    let certificate = workspace.join("li_site_ca_certificate.pem");
    fs::write(&certificate, certificate_pem("ca")).expect("certificate");
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o644))
        .expect("unsafe certificate mode");
    assert!(io
        .read_private_file(&certificate, 64 * 1024, owner)
        .is_err());
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o600))
        .expect("private certificate mode");
    let link = workspace.join("li_site_public_key.pem");
    std::os::unix::fs::symlink(&key, &link).expect("link");
    assert!(io.read_private_file(&link, 8 * 1024, owner).is_err());
    fs::remove_file(link).expect("remove link");
    io.remove_workspace(&workspace, owner).expect("cleanup");
}

// Removes only the closed trust file set and makes exact cleanup idempotent.
#[test]
fn system_trust_workspace_cleanup_is_closed_and_idempotent() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let owner = fs::metadata(directory.path()).expect("owner").uid();
    let root = directory.path().join("pairing_trust_staging");
    let workspace = root.join("workspace");
    let io = SystemPairingTrustWorkspaceIo;
    io.ensure_private_root(&root, owner).expect("root");
    io.create_private_workspace(&workspace, owner)
        .expect("workspace");
    io.write_private_file(
        &workspace.join("li_enrollment_transcript.bin"),
        b"transcript",
        64 * 1024,
        owner,
    )
    .expect("input");
    assert!(io.remove_workspace(&workspace, owner).expect("remove"));
    assert!(!io
        .remove_workspace(&workspace, owner)
        .expect("idempotent remove"));

    io.create_private_workspace(&workspace, owner)
        .expect("second workspace");
    fs::write(workspace.join("foreign"), b"foreign").expect("foreign");
    fs::set_permissions(workspace.join("foreign"), fs::Permissions::from_mode(0o600))
        .expect("foreign mode");
    assert!(io.remove_workspace(&workspace, owner).is_err());
    fs::remove_file(workspace.join("foreign")).expect("remove foreign");
    assert!(io
        .remove_workspace(&workspace, owner)
        .expect("final cleanup"));
}

// Identifies one fixed OpenSSL call from its exact argv.
fn command_operation(arguments: &[String]) -> &'static str {
    let first = arguments.first().map(String::as_str);
    if first == Some("pkey") && arguments.iter().any(|value| value == "-pubcheck") {
        return "candidate-key";
    }
    if first == Some("pkey") {
        let input = input_path(arguments);
        return match input.file_name().and_then(|value| value.to_str()) {
            Some("li_site_public_key.pem") => "site-public",
            Some("li_site_private_key.pem") => "site-private",
            Some("li_site_ca_public_key.pem") => "ca-public",
            Some("li_member_certificate_public_key.pem") => "certificate-public-der",
            value => panic!("unexpected pkey input: {value:?}"),
        };
    }
    if first == Some("verify") {
        return "verify-certificate";
    }
    if first == Some("dgst") && arguments.iter().any(|value| value == "-verify") {
        return "verify-proof";
    }
    if first == Some("dgst") && arguments.iter().any(|value| value == "-sign") {
        return "sign-membership";
    }
    if first == Some("x509") && arguments.iter().any(|value| value == "-new") {
        return "issue-certificate";
    }
    if first == Some("x509") && arguments.iter().any(|value| value == "-checkend") {
        return "check-certificate";
    }
    if first == Some("x509") && arguments.iter().any(|value| value == "-startdate") {
        return "member-validity";
    }
    if first == Some("x509") && arguments.iter().any(|value| value == "subjectAltName") {
        return "member-uri";
    }
    if first == Some("x509") && arguments.iter().any(|value| value == "-pubkey") {
        return match input_path(arguments)
            .file_name()
            .and_then(|value| value.to_str())
        {
            Some("li_site_ca_certificate.pem") => "ca-public-pem",
            Some("li_member_certificate.pem") => "certificate-public",
            value => panic!("unexpected certificate public input: {value:?}"),
        };
    }
    if first == Some("x509") && arguments.iter().any(|value| value == "DER") {
        return match input_path(arguments)
            .file_name()
            .and_then(|value| value.to_str())
        {
            Some("li_site_ca_certificate.pem") => "ca-certificate-der",
            Some("li_local_control_certificate.pem") => "local-certificate-der",
            Some("li_member_certificate.pem") => "member-certificate-der",
            value => panic!("unexpected certificate DER input: {value:?}"),
        };
    }
    panic!("unexpected OpenSSL argv: {arguments:?}")
}

// Returns the path following one exact argv option.
fn option_path(arguments: &[String], option: &str) -> PathBuf {
    let index = arguments
        .iter()
        .position(|value| value == option)
        .expect("option");
    PathBuf::from(arguments.get(index + 1).expect("option value"))
}

// Returns one command input path.
fn input_path(arguments: &[String]) -> PathBuf {
    option_path(arguments, "-in")
}

// Returns one command output path.
fn output_path(arguments: &[String]) -> PathBuf {
    option_path(arguments, "-out")
}

// Writes deterministic bytes into one pre-created command output.
fn write_output(arguments: &[String], payload: &[u8]) {
    fs::write(output_path(arguments), payload).expect("command output");
}

// Returns one exact uncompressed canonical P-256 SPKI fixture.
fn p256_spki(point: u8) -> Vec<u8> {
    let mut value = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    value.extend([point; 64]);
    value
}

// Returns the candidate P-256 SPKI fixture.
fn candidate_spki() -> Vec<u8> {
    p256_spki(0x11)
}

// Returns the site P-256 SPKI fixture.
fn site_spki() -> Vec<u8> {
    p256_spki(0x22)
}

// Returns a bounded candidate PEM fixture.
fn public_key_pem() -> Vec<u8> {
    pem("PUBLIC KEY", 'A', 160)
}

// Returns a bounded site public PEM fixture.
fn site_public_key_pem() -> Vec<u8> {
    pem("PUBLIC KEY", 'B', 160)
}

// Returns a bounded site private PEM fixture.
fn private_key_pem() -> Vec<u8> {
    pem("PRIVATE KEY", 'C', 160)
}

// Returns one bounded certificate PEM fixture.
fn certificate_pem(label: &str) -> Vec<u8> {
    let character = match label {
        "ca" => 'D',
        "local" => 'E',
        "member" => 'F',
        _ => panic!("unknown certificate fixture"),
    };
    pem("CERTIFICATE", character, 320)
}

// Creates one stable ASCII PEM envelope.
fn pem(kind: &str, character: char, body_bytes: usize) -> Vec<u8> {
    format!(
        "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
        character.to_string().repeat(body_bytes)
    )
    .into_bytes()
}

// Returns one lowercase SHA-256 fixture identity.
fn digest(payload: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(payload))).expect("digest")
}

// Returns whether one byte buffer contains another contiguously.
fn contains(payload: &[u8], expected: &[u8]) -> bool {
    payload
        .windows(expected.len())
        .any(|window| window == expected)
}
