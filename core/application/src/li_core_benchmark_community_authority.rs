// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::OpenOptions;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use li_benchmark_manager::{
    BenchmarkCommunityAuthority, BenchmarkGitRevision, BenchmarkKind, BenchmarkRequest,
};
use li_core_interface::Sha256Digest;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{CoreBenchmarkCommunityAuthorityPort, CoreBenchmarkPortError};

const MAXIMUM_SNAPSHOT_BYTES: usize = 128 * 1024;
const MAXIMUM_PAYLOAD_BYTES: usize = 64 * 1024;
const MAXIMUM_AUTHORITY_LIFETIME_MILLISECONDS: u64 = 15 * 60 * 1000;

// Reads one exact credential-free authority snapshot from its trusted handoff root.
pub trait CoreBenchmarkCommunityAuthorityReader: Send + Sync {
    // Reads no more than the requested bound or fails without returning partial content.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, CoreBenchmarkPortError>;
}

// Supplies deterministic wall time for snapshot freshness checks.
pub trait CoreBenchmarkCommunityAuthorityClock: Send + Sync {
    // Returns current Unix time in milliseconds.
    fn now_unix_milliseconds(&self) -> Result<u64, CoreBenchmarkPortError>;
}

// Uses bounded ordinary files supplied by the privileged proposal acquisition boundary.
pub struct SystemCoreBenchmarkCommunityAuthorityReader;

impl CoreBenchmarkCommunityAuthorityReader for SystemCoreBenchmarkCommunityAuthorityReader {
    // Rejects missing, non-regular, or oversized snapshots before parsing them.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, CoreBenchmarkPortError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(path)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum_bytes as u64 {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        let mut value = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut value)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        if value.len() > maximum_bytes {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        Ok(value)
    }
}

// Uses the operating-system wall clock only through the injectable clock boundary.
pub struct SystemCoreBenchmarkCommunityAuthorityClock;

impl CoreBenchmarkCommunityAuthorityClock for SystemCoreBenchmarkCommunityAuthorityClock {
    // Converts the system clock without accepting pre-epoch or overflowing values.
    fn now_unix_milliseconds(&self) -> Result<u64, CoreBenchmarkPortError> {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .as_millis();
        u64::try_from(milliseconds).map_err(|_| CoreBenchmarkPortError::Unavailable)
    }
}

// Verifies exact signed proposal snapshots without GitHub or other network credentials.
pub struct FilesystemCoreBenchmarkCommunityAuthority {
    root: PathBuf,
    public_key: [u8; 32],
    key_sha256: String,
    reader: Arc<dyn CoreBenchmarkCommunityAuthorityReader>,
    clock: Arc<dyn CoreBenchmarkCommunityAuthorityClock>,
}

impl FilesystemCoreBenchmarkCommunityAuthority {
    // Loads one production adapter from an explicit snapshot root and Ed25519 public key file.
    pub fn load(root: PathBuf, public_key_file: PathBuf) -> Result<Self, CoreBenchmarkPortError> {
        let reader = Arc::new(SystemCoreBenchmarkCommunityAuthorityReader);
        let public_key_pem = reader.read(&public_key_file, 4_096)?;
        let public_key = ed25519_public_key(&public_key_pem)?;
        Self::new(
            root,
            public_key,
            reader,
            Arc::new(SystemCoreBenchmarkCommunityAuthorityClock),
        )
    }

    // Creates an adapter with injectable file and time providers for deterministic verification.
    pub fn new(
        root: PathBuf,
        public_key: Vec<u8>,
        reader: Arc<dyn CoreBenchmarkCommunityAuthorityReader>,
        clock: Arc<dyn CoreBenchmarkCommunityAuthorityClock>,
    ) -> Result<Self, CoreBenchmarkPortError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let key_sha256 = hex_digest(&public_key);
        Ok(Self {
            root,
            public_key,
            key_sha256,
            reader,
            clock,
        })
    }
}

// Extracts one exact Ed25519 SubjectPublicKeyInfo PEM without accepting another algorithm.
fn ed25519_public_key(pem: &[u8]) -> Result<Vec<u8>, CoreBenchmarkPortError> {
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut cursor = Cursor::new(pem);
    let keys = rustls_pemfile::public_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
    let [der] = keys.as_slice() else {
        return Err(CoreBenchmarkPortError::InvalidState);
    };
    let der = der.as_ref();
    if der.len() != ED25519_SPKI_PREFIX.len() + 32
        || !der.starts_with(&ED25519_SPKI_PREFIX)
        || cursor.position() != pem.len() as u64
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    Ok(der[ED25519_SPKI_PREFIX.len()..].to_vec())
}

impl CoreBenchmarkCommunityAuthorityPort for FilesystemCoreBenchmarkCommunityAuthority {
    // Verifies signature, freshness, and every immutable request identity before authorization.
    fn authority(
        &self,
        _job_id: &li_core_interface::OperationId,
        request: &BenchmarkRequest,
    ) -> Result<BenchmarkCommunityAuthority, CoreBenchmarkPortError> {
        let request_sha256 = request
            .sha256()
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let path = self
            .root
            .join(format!("{}.authority.json", request_sha256.as_str()));
        let document = self.reader.read(&path, MAXIMUM_SNAPSHOT_BYTES)?;
        let envelope: AuthorityEnvelope =
            serde_json::from_slice(&document).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        if envelope.schema_name != "li-benchmark-community-authority-envelope"
            || envelope.schema_version != 1
            || envelope.signature_algorithm != "ed25519"
            || envelope.signing_key_sha256 != self.key_sha256
        {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        let payload = STANDARD
            .decode(&envelope.payload_base64)
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let signature = STANDARD
            .decode(&envelope.signature_base64)
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        if payload.is_empty()
            || payload.len() > MAXIMUM_PAYLOAD_BYTES
            || envelope.payload_sha256 != hex_digest(&payload)
            || signature.len() != 64
            || UnparsedPublicKey::new(&ED25519, self.public_key)
                .verify(&payload, &signature)
                .is_err()
        {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        let payload: AuthorityPayload =
            serde_json::from_slice(&payload).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        validate_payload(
            &payload,
            request,
            &request_sha256,
            self.clock.now_unix_milliseconds()?,
        )?;
        BenchmarkCommunityAuthority::new(
            payload.pull_request,
            BenchmarkGitRevision::parse(&payload.proposal_head)
                .map_err(|_| CoreBenchmarkPortError::InvalidState)?,
            &payload.candidate_id,
            Sha256Digest::parse(&payload.candidate_subject_sha256)
                .map_err(|_| CoreBenchmarkPortError::InvalidState)?,
            payload.verifier_numeric_id,
            Sha256Digest::parse(&payload.device_id)
                .map_err(|_| CoreBenchmarkPortError::InvalidState)?,
            payload
                .baseline_execution_sha256
                .as_deref()
                .map(Sha256Digest::parse)
                .transpose()
                .map_err(|_| CoreBenchmarkPortError::InvalidState)?,
            true,
            true,
        )
        .map_err(|_| CoreBenchmarkPortError::InvalidState)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEnvelope {
    schema_name: String,
    schema_version: u32,
    payload_base64: String,
    payload_sha256: String,
    signature_algorithm: String,
    signing_key_sha256: String,
    signature_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityPayload {
    schema_name: String,
    schema_version: u32,
    repository: String,
    request_sha256: String,
    pull_request: u64,
    proposal_head: String,
    candidate_id: String,
    candidate_subject_sha256: String,
    transaction_id: String,
    verifier_numeric_id: u64,
    device_id: String,
    baseline_execution_sha256: Option<String>,
    verifier_bundle_sha256: String,
    model: String,
    runtime_execution_sha256: String,
    benchmark_contract_sha256: String,
    target_contract_sha256: String,
    benchmark_ready: bool,
    verifier_bundle_verified: bool,
    issued_at_unix_milliseconds: u64,
    expires_at_unix_milliseconds: u64,
}

// Rejects expired, overlong, or request-mismatched signed authority payloads.
fn validate_payload(
    payload: &AuthorityPayload,
    request: &BenchmarkRequest,
    request_sha256: &Sha256Digest,
    now: u64,
) -> Result<(), CoreBenchmarkPortError> {
    if payload.schema_name != "li-benchmark-community-authority"
        || payload.schema_version != 1
        || payload.repository != "letsinferlabs/runtimes"
        || !payload.benchmark_ready
        || !payload.verifier_bundle_verified
        || Sha256Digest::parse(&payload.verifier_bundle_sha256).is_err()
        || payload.issued_at_unix_milliseconds > now
        || now >= payload.expires_at_unix_milliseconds
        || payload
            .expires_at_unix_milliseconds
            .saturating_sub(payload.issued_at_unix_milliseconds)
            > MAXIMUM_AUTHORITY_LIFETIME_MILLISECONDS
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    let BenchmarkKind::Verification {
        pull_request,
        proposal_head,
        candidate,
        transaction_id,
        verifier_bundle_sha256,
        candidate_subject_sha256,
        verifier_numeric_id,
        device_id,
        baseline_execution_sha256,
    } = request.kind()
    else {
        return Err(CoreBenchmarkPortError::Conflict);
    };
    let subject = request.subject();
    let matches = payload.request_sha256 == request_sha256.as_str()
        && payload.pull_request == *pull_request
        && payload.proposal_head == proposal_head.as_str()
        && payload.candidate_id == candidate.as_str()
        && payload.candidate_subject_sha256 == candidate_subject_sha256.as_str()
        && payload.transaction_id == transaction_id.as_str()
        && payload.verifier_bundle_sha256 == verifier_bundle_sha256.as_str()
        && payload.verifier_numeric_id == *verifier_numeric_id
        && payload.device_id == device_id.as_str()
        && payload.baseline_execution_sha256.as_deref()
            == baseline_execution_sha256.as_ref().map(Sha256Digest::as_str)
        && payload.model == subject.model().as_str()
        && payload.runtime_execution_sha256 == subject.execution_sha256().as_str()
        && payload.benchmark_contract_sha256 == subject.benchmark_contract_sha256().as_str()
        && payload.target_contract_sha256 == subject.target_contract_sha256().as_str();
    if !matches {
        return Err(CoreBenchmarkPortError::Conflict);
    }
    Ok(())
}

// Returns the lowercase SHA-256 identity of exact bytes.
fn hex_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use li_benchmark_manager::{BenchmarkScope, BenchmarkSubject};
    use li_core_interface::{
        InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
        RuntimeInstallationId,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::{json, Value};
    use tempfile::tempdir;

    use super::*;

    struct FixedReader(Mutex<Option<Vec<u8>>>);

    impl CoreBenchmarkCommunityAuthorityReader for FixedReader {
        // Returns the injected snapshot or one deterministic provider failure.
        fn read(
            &self,
            _path: &Path,
            _maximum_bytes: usize,
        ) -> Result<Vec<u8>, CoreBenchmarkPortError> {
            self.0
                .lock()
                .expect("reader")
                .clone()
                .ok_or(CoreBenchmarkPortError::Unavailable)
        }
    }

    struct FixedClock(u64);

    impl CoreBenchmarkCommunityAuthorityClock for FixedClock {
        // Returns the injected admission time.
        fn now_unix_milliseconds(&self) -> Result<u64, CoreBenchmarkPortError> {
            Ok(self.0)
        }
    }

    // Returns one exact lowercase digest fixture.
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
    }

    // Returns one complete community-verification request.
    fn request(execution: char, target: char) -> BenchmarkRequest {
        BenchmarkRequest::new(
            BenchmarkKind::verification(
                41,
                BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
                RuntimeCandidateId::parse("vllm--owner--model--spark").expect("candidate"),
                li_core_interface::OperationId::parse(&"d".repeat(32)).expect("transaction"),
                digest('e'),
                digest('f'),
                73,
                digest('b'),
                Some(digest('c')),
            )
            .expect("kind"),
            BenchmarkScope::Complete,
            BenchmarkSubject::new(
                InstallationId::parse(&"1".repeat(64)).expect("installation"),
                RuntimeInstallationId::parse(&"2".repeat(32)).expect("runtime installation"),
                LogicalModelName::parse("model").expect("model"),
                PlacementGroupId::parse(&"3".repeat(32)).expect("group"),
                digest(execution),
                digest('5'),
                digest(target),
            ),
        )
        .expect("request")
    }

    // Creates one correctly signed snapshot, optionally changing signed payload fields.
    fn fixture(request: &BenchmarkRequest, mutate: impl FnOnce(&mut Value)) -> (Vec<u8>, Vec<u8>) {
        let request_sha256 = request.sha256().expect("request digest");
        let mut payload = json!({
            "schema_name": "li-benchmark-community-authority", "schema_version": 1,
            "repository": "letsinferlabs/runtimes", "request_sha256": request_sha256.as_str(),
            "pull_request": 41, "proposal_head": "a".repeat(40),
            "candidate_id": "vllm--owner--model--spark",
            "candidate_subject_sha256": "f".repeat(64), "transaction_id": "d".repeat(32),
            "verifier_numeric_id": 73,
            "device_id": "b".repeat(64), "baseline_execution_sha256": "c".repeat(64),
            "verifier_bundle_sha256": "e".repeat(64),
            "model": "model", "runtime_execution_sha256": "4".repeat(64),
            "benchmark_contract_sha256": "5".repeat(64), "target_contract_sha256": "6".repeat(64),
            "benchmark_ready": true, "verifier_bundle_verified": true,
            "issued_at_unix_milliseconds": 1_000, "expires_at_unix_milliseconds": 2_000
        });
        mutate(&mut payload);
        let payload = serde_json::to_vec(&payload).expect("payload");
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("key");
        let signature = pair.sign(&payload);
        let envelope = json!({
            "schema_name": "li-benchmark-community-authority-envelope", "schema_version": 1,
            "payload_base64": STANDARD.encode(&payload), "payload_sha256": hex_digest(&payload),
            "signature_algorithm": "ed25519", "signing_key_sha256": hex_digest(pair.public_key().as_ref()),
            "signature_base64": STANDARD.encode(signature.as_ref())
        });
        (
            serde_json::to_vec(&envelope).expect("envelope"),
            pair.public_key().as_ref().to_vec(),
        )
    }

    // Creates the production adapter around deterministic providers.
    fn adapter(
        document: Option<Vec<u8>>,
        key: Vec<u8>,
        now: u64,
    ) -> FilesystemCoreBenchmarkCommunityAuthority {
        FilesystemCoreBenchmarkCommunityAuthority::new(
            PathBuf::from("/authority"),
            key,
            Arc::new(FixedReader(Mutex::new(document))),
            Arc::new(FixedClock(now)),
        )
        .expect("adapter")
    }

    // Encodes one raw Ed25519 key in the exact SubjectPublicKeyInfo PEM used by setup.
    fn public_key_pem(public_key: &[u8]) -> Vec<u8> {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(public_key);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
        .into_bytes()
    }

    #[test]
    // Accepts setup's exact Ed25519 PEM/SPKI representation and no other algorithm framing.
    fn ed25519_pem_extracts_the_exact_raw_key() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("key");
        assert_eq!(
            ed25519_public_key(&public_key_pem(pair.public_key().as_ref())).expect("PEM"),
            pair.public_key().as_ref()
        );
    }

    #[test]
    // Refuses a final-component symlink before reading authority material.
    fn production_reader_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("directory");
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::write(&target, b"authority").expect("target");
        symlink(&target, &link).expect("symlink");
        assert_eq!(
            SystemCoreBenchmarkCommunityAuthorityReader.read(&link, 128),
            Err(CoreBenchmarkPortError::Unavailable)
        );
    }

    #[test]
    // Preserves the exact authorization identity across an idempotent replay.
    fn exact_snapshot_is_replay_safe_and_deterministic() {
        let request = request('4', '6');
        let (document, key) = fixture(&request, |_| {});
        let authority = adapter(Some(document), key, 1_500);
        let job = OperationId::parse(&"d".repeat(32)).expect("job");
        let first = authority.authority(&job, &request).expect("authority");
        let replay = authority.authority(&job, &request).expect("replay");
        assert_eq!(first, replay);
    }

    #[test]
    // Rejects stale authority and exact signed execution or target drift.
    fn expired_runtime_and_target_mismatches_fail_closed() {
        let base = request('4', '6');
        let (document, key) = fixture(&base, |_| {});
        let job = OperationId::parse(&"d".repeat(32)).expect("job");
        assert_eq!(
            adapter(Some(document.clone()), key.clone(), 2_000).authority(&job, &base),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        let wrong_runtime = request('7', '6');
        let (wrong_runtime_document, _) = fixture(&wrong_runtime, |_| {});
        assert_eq!(
            adapter(Some(wrong_runtime_document), key.clone(), 1_500)
                .authority(&job, &wrong_runtime),
            Err(CoreBenchmarkPortError::Conflict)
        );
        let wrong_target = request('4', '8');
        let (wrong_target_document, _) = fixture(&wrong_target, |_| {});
        assert_eq!(
            adapter(Some(wrong_target_document), key, 1_500).authority(&job, &wrong_target),
            Err(CoreBenchmarkPortError::Conflict)
        );
    }

    #[test]
    // Redacts both cryptographic failure and unavailable snapshot-provider details.
    fn bad_signature_and_unavailable_provider_fail_closed() {
        let request = request('4', '6');
        let (document, key) = fixture(&request, |_| {});
        let mut envelope: Value = serde_json::from_slice(&document).expect("envelope");
        envelope["signature_base64"] = Value::String(STANDARD.encode([0_u8; 64]));
        let document = serde_json::to_vec(&envelope).expect("bad signature envelope");
        let job = OperationId::parse(&"d".repeat(32)).expect("job");
        assert_eq!(
            adapter(Some(document), key.clone(), 1_500).authority(&job, &request),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        assert_eq!(
            adapter(None, key, 1_500).authority(&job, &request),
            Err(CoreBenchmarkPortError::Unavailable)
        );
    }
}
