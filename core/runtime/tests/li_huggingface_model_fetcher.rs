// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture, EngineDistribution,
    EvidenceLabel, GgufFileIdentity, LogicalModelName, MemoryTopology, ModelArtifact,
    ModelArtifactFormat, OperatingSystem, RuntimeCandidateId, RuntimeIdentity, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TechnicalName,
};
use li_runtime_manager::{
    ComposedRuntimeArtifactFetcher, HuggingFaceRuntimeModelFetcher, RuntimeAcceleratorVendor,
    RuntimeArtifactFetcher, RuntimeCandidate, RuntimeEngineArtifactFetcher, RuntimeError,
    RuntimeHttpClient, RuntimeHttpDownload, RuntimeHttpRequest, RuntimeHttpResponse,
    RuntimeModelArtifactFetcher, RuntimeModelArtifactIo, RuntimePackArtifactFetcher, RuntimeTarget,
    SystemRuntimeModelArtifactIo,
};
use sha2::{Digest, Sha256};

// Returns one canonical SHA-256 for fixture bytes.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns one complete-snapshot model artifact.
fn snapshot_artifact() -> ModelArtifact {
    ModelArtifact::new(
        ArtifactName::parse("model").expect("name"),
        ArtifactUri::parse("hf://FixtureOrg/Fixture-Model").expect("URI"),
        ArtifactRevision::parse(&"1".repeat(40)).expect("revision"),
        ModelArtifactFormat::HuggingFaceSnapshot,
    )
}

// Returns one exact GGUF model artifact.
fn gguf_artifact(bytes: Option<u64>) -> ModelArtifact {
    ModelArtifact::new(
        ArtifactName::parse("model").expect("name"),
        ArtifactUri::parse("hf://FixtureOrg/Fixture-GGUF").expect("URI"),
        ArtifactRevision::parse(&"2".repeat(40)).expect("revision"),
        ModelArtifactFormat::GgufFile(
            GgufFileIdentity::new("fixture.gguf", digest(b"gguf"), bytes).expect("GGUF"),
        ),
    )
}

// Returns one exact Linux OCI candidate for composed Engine delegation.
fn engine_candidate() -> RuntimeCandidate {
    RuntimeCandidate::new(
        LogicalModelName::parse("fixture-model").expect("model"),
        RuntimeIdentity::new(
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            RuntimeVersion::parse("1.0.0").expect("version"),
            TargetId::parse("target").expect("target"),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/runtime@sha256:{}",
                "3".repeat(64)
            ))
            .expect("runtime source"),
            EngineDistribution::oci(
                RuntimeSource::parse(&format!(
                    "ghcr.io/letsinferlabs/engine@sha256:{}",
                    "5".repeat(64)
                ))
                .expect("Engine source"),
                Sha256Digest::parse(&"6".repeat(64)).expect("Engine ID"),
                None,
                None,
            ),
            Sha256Digest::parse(&"3".repeat(64)).expect("runtime digest"),
            Sha256Digest::parse(&"7".repeat(64)).expect("manifest digest"),
            Sha256Digest::parse(&"8".repeat(64)).expect("execution digest"),
        )
        .expect("runtime"),
        vec![snapshot_artifact()],
        RuntimeTarget::new(
            OperatingSystem::Linux,
            CpuArchitecture::Arm64,
            RuntimeAcceleratorVendor::Nvidia,
            TechnicalName::parse("sm_121").expect("architecture"),
            1,
            MemoryTopology::Unified,
            None,
            ByteCount::new(1).expect("memory"),
        )
        .expect("target"),
        EvidenceLabel::Unqualified,
        2,
        false,
        false,
    )
    .expect("candidate")
}

// Creates one validated deterministic metadata response.
fn response(body: serde_json::Value, link: Option<&str>) -> RuntimeHttpResponse {
    let headers = link
        .map(|value| BTreeMap::from([("link".to_string(), value.to_string())]))
        .unwrap_or_default();
    RuntimeHttpResponse::new(
        200,
        "https://huggingface.co/api/models/fixture".to_string(),
        headers,
        serde_json::to_vec(&body).expect("body"),
        false,
    )
    .expect("response")
}

// Configures one deterministic streamed download result.
struct MockDownload {
    bytes: Vec<u8>,
    reported_bytes: Option<u64>,
    reported_sha256: Option<Sha256Digest>,
    error: Option<RuntimeError>,
}

impl MockDownload {
    // Creates one truthful successful download.
    fn success(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            reported_bytes: None,
            reported_sha256: None,
            error: None,
        }
    }
}

// Mocks exact metadata pages and streamed files while recording every request.
struct MockHttp {
    responses: Mutex<VecDeque<Result<RuntimeHttpResponse, RuntimeError>>>,
    downloads: Mutex<VecDeque<MockDownload>>,
    gets: Mutex<Vec<(String, u64)>>,
    files: Mutex<Vec<(String, PathBuf, u64)>>,
}

impl MockHttp {
    // Creates one HTTP fixture from ordered metadata and file results.
    fn new(responses: Vec<RuntimeHttpResponse>, downloads: Vec<MockDownload>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().map(Ok).collect()),
            downloads: Mutex::new(downloads.into()),
            gets: Mutex::new(Vec::new()),
            files: Mutex::new(Vec::new()),
        }
    }
}

impl RuntimeHttpClient for MockHttp {
    // Returns the next metadata result and records its exact bound.
    fn get(
        &self,
        request: &RuntimeHttpRequest,
        maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpResponse, RuntimeError> {
        self.gets
            .lock()
            .expect("gets")
            .push((request.url().to_string(), maximum_body_bytes));
        self.responses
            .lock()
            .expect("responses")
            .pop_front()
            .unwrap_or(Err(RuntimeError::DownloadUnavailable))
    }

    // Writes the next deterministic file and returns its configured measured identity.
    fn download(
        &self,
        request: &RuntimeHttpRequest,
        destination: &Path,
        maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpDownload, RuntimeError> {
        self.files.lock().expect("files").push((
            request.url().to_string(),
            destination.to_path_buf(),
            maximum_body_bytes,
        ));
        let value = self
            .downloads
            .lock()
            .expect("downloads")
            .pop_front()
            .ok_or(RuntimeError::DownloadUnavailable)?;
        if let Some(error) = value.error {
            return Err(error);
        }
        fs::write(destination, &value.bytes).map_err(|_| RuntimeError::DownloadUnavailable)?;
        RuntimeHttpDownload::new(
            200,
            "https://cdn-lfs.huggingface.co/object".to_string(),
            BTreeMap::new(),
            value.reported_bytes.unwrap_or(value.bytes.len() as u64),
            value
                .reported_sha256
                .unwrap_or_else(|| digest(&value.bytes)),
            false,
        )
    }
}

// Wraps real model I/O and fails one named external boundary.
struct FailingModelIo {
    system: SystemRuntimeModelArtifactIo,
    step: Mutex<Option<&'static str>>,
    clears: AtomicUsize,
}

impl FailingModelIo {
    // Creates one real-I/O wrapper with no configured failure.
    fn new() -> Self {
        Self {
            system: SystemRuntimeModelArtifactIo,
            step: Mutex::new(None),
            clears: AtomicUsize::new(0),
        }
    }

    // Returns whether one exact I/O boundary is configured to fail.
    fn fails(&self, step: &'static str) -> bool {
        self.step.lock().expect("step").as_ref() == Some(&step)
    }
}

impl RuntimeModelArtifactIo for FailingModelIo {
    // Prepares one destination or returns the configured failure.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        if self.fails("prepare") {
            return Err(RuntimeError::ModelAcquisitionUnavailable);
        }
        self.system.prepare_destination(destination)
    }

    // Creates one parent or returns the configured failure.
    fn create_parent(&self, destination: &Path, relative: &Path) -> Result<(), RuntimeError> {
        if self.fails("parent") {
            return Err(RuntimeError::ModelAcquisitionUnavailable);
        }
        self.system.create_parent(destination, relative)
    }

    // Seals one file or returns the configured failure.
    fn seal_file(&self, path: &Path) -> Result<(), RuntimeError> {
        if self.fails("seal") {
            return Err(RuntimeError::ModelAcquisitionUnavailable);
        }
        self.system.seal_file(path)
    }

    // Writes one receipt or returns the configured failure.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError> {
        if self.fails("receipt") {
            return Err(RuntimeError::ModelAcquisitionUnavailable);
        }
        self.system.write_receipt(destination, receipt)
    }

    // Clears one failed acquisition or returns the configured failure.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        self.clears.fetch_add(1, Ordering::SeqCst);
        if self.fails("clear") {
            return Err(RuntimeError::ModelAcquisitionUnavailable);
        }
        self.system.clear_destination(destination)
    }
}

// Creates one empty owner-only model destination.
fn model_destination(directory: &tempfile::TempDir) -> PathBuf {
    let destination = directory.path().join("model");
    fs::create_dir(&destination).expect("destination");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    destination
}

// Acquires a paginated snapshot in sorted path order with exact LFS verification.
#[test]
fn snapshot_acquisition_is_closed_paginated_and_deterministic() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = model_destination(&directory);
    let next = "https://huggingface.co/api/models/FixtureOrg/Fixture-Model/tree/next";
    let page_one = response(
        serde_json::json!([
            {"type": "directory", "path": "nested", "size": 0},
            {"type": "file", "path": "weights.bin", "size": 3, "lfs": {"oid": format!("sha256:{}", digest(b"bin").as_str())}},
            {"type": "file", "path": "config.json", "size": 2}
        ]),
        Some(&format!("<{next}>; rel=\"next\"")),
    );
    let page_two = response(
        serde_json::json!([
            {"type": "file", "path": "nested/tokenizer.json", "size": 3}
        ]),
        None,
    );
    let http = Arc::new(MockHttp::new(
        vec![page_one, page_two],
        vec![
            MockDownload::success(b"{}"),
            MockDownload::success(b"tok"),
            MockDownload::success(b"bin"),
        ],
    ));
    let io = Arc::new(FailingModelIo::new());
    let fetcher = HuggingFaceRuntimeModelFetcher::new(http.clone(), io);
    fetcher
        .fetch(&snapshot_artifact(), &destination)
        .expect("acquire");
    assert_eq!(
        fs::read(destination.join("config.json")).expect("config"),
        b"{}"
    );
    assert_eq!(
        fs::read(destination.join("nested/tokenizer.json")).expect("tokenizer"),
        b"tok"
    );
    assert_eq!(
        fs::read(destination.join("weights.bin")).expect("weights"),
        b"bin"
    );
    let files = http.files.lock().expect("files");
    assert!(files[0].0.ends_with("/config.json?download=true"));
    assert!(files[1].0.ends_with("/nested/tokenizer.json?download=true"));
    assert!(files[2].0.ends_with("/weights.bin?download=true"));
    assert_eq!(http.gets.lock().expect("gets").len(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(destination.join("weights.bin"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

// Downloads only the declared GGUF file and binds runtime, metadata, size, and bytes.
#[test]
fn gguf_acquisition_filters_and_verifies_exact_file_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = model_destination(&directory);
    let http = Arc::new(MockHttp::new(
        vec![response(
            serde_json::json!([
                {"type": "file", "path": "README.md", "size": 10},
                {"type": "file", "path": "fixture.gguf", "size": 4, "lfs": {"oid": format!("sha256:{}", digest(b"gguf").as_str())}}
            ]),
            None,
        )],
        vec![MockDownload::success(b"gguf")],
    ));
    let fetcher =
        HuggingFaceRuntimeModelFetcher::new(http.clone(), Arc::new(SystemRuntimeModelArtifactIo));
    fetcher
        .fetch(&gguf_artifact(Some(4)), &destination)
        .expect("GGUF");
    assert_eq!(
        fs::read(destination.join("fixture.gguf")).expect("GGUF"),
        b"gguf"
    );
    assert_eq!(http.files.lock().expect("files").len(), 1);
}

// Rejects malformed, duplicate, unsafe, unbounded, and incomplete metadata before download.
#[test]
fn metadata_mutation_matrix_fails_closed_without_partial_files() {
    let mutations = vec![
        serde_json::json!({"not": "an array"}),
        serde_json::json!([{"type": "link", "path": "x", "size": 1}]),
        serde_json::json!([{"type": "file", "path": "../escape", "size": 1}]),
        serde_json::json!([
            {"type": "file", "path": "same", "size": 1},
            {"type": "file", "path": "same", "size": 1}
        ]),
        serde_json::json!([{"type": "file", "path": "x", "size": -1}]),
        serde_json::json!([{"type": "file", "path": "x", "size": 1, "lfs": {"oid": "wrong"}}]),
        serde_json::json!([]),
    ];
    for (index, body) in mutations.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = model_destination(&directory);
        let http = Arc::new(MockHttp::new(vec![response(body, None)], Vec::new()));
        let fetcher = HuggingFaceRuntimeModelFetcher::new(
            http.clone(),
            Arc::new(SystemRuntimeModelArtifactIo),
        );
        assert_eq!(
            fetcher
                .fetch(&snapshot_artifact(), &destination)
                .expect_err("metadata"),
            RuntimeError::ModelAcquisitionInvalid,
            "mutation={index}"
        );
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
        assert!(http.files.lock().expect("files").is_empty());
    }
}

// Rejects malformed and cyclic pagination plus non-success metadata responses.
#[test]
fn pagination_and_status_failures_are_bounded() {
    for link in [
        "not-a-link; rel=\"next\"",
        "<http://huggingface.co/next>; rel=\"next\"",
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = model_destination(&directory);
        let fetcher = HuggingFaceRuntimeModelFetcher::new(
            Arc::new(MockHttp::new(
                vec![response(
                    serde_json::json!([{"type": "file", "path": "x", "size": 1}]),
                    Some(link),
                )],
                Vec::new(),
            )),
            Arc::new(SystemRuntimeModelArtifactIo),
        );
        assert!(fetcher.fetch(&snapshot_artifact(), &destination).is_err());
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = model_destination(&directory);
    let initial = format!(
        "https://huggingface.co/api/models/FixtureOrg/Fixture-Model/tree/{}?recursive=true&limit=1000",
        "1".repeat(40)
    );
    let fetcher = HuggingFaceRuntimeModelFetcher::new(
        Arc::new(MockHttp::new(
            vec![response(
                serde_json::json!([{"type": "file", "path": "x", "size": 1}]),
                Some(&format!("<{initial}>; rel=\"next\"")),
            )],
            Vec::new(),
        )),
        Arc::new(SystemRuntimeModelArtifactIo),
    );
    assert_eq!(
        fetcher
            .fetch(&snapshot_artifact(), &destination)
            .expect_err("cycle"),
        RuntimeError::ModelAcquisitionInvalid
    );

    let mut unavailable = response(serde_json::json!([]), None);
    unavailable = RuntimeHttpResponse::new(
        503,
        unavailable.final_url().to_string(),
        BTreeMap::new(),
        Vec::new(),
        false,
    )
    .expect("response");
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = model_destination(&directory);
    let fetcher = HuggingFaceRuntimeModelFetcher::new(
        Arc::new(MockHttp::new(vec![unavailable], Vec::new())),
        Arc::new(SystemRuntimeModelArtifactIo),
    );
    assert_eq!(
        fetcher
            .fetch(&snapshot_artifact(), &destination)
            .expect_err("status"),
        RuntimeError::ModelAcquisitionUnavailable
    );
}

// Rejects metadata/runtime GGUF disagreement before downloading any bytes.
#[test]
fn gguf_metadata_mismatch_fails_before_download() {
    for entry in [
        serde_json::json!({"type": "file", "path": "fixture.gguf", "size": 5, "lfs": {"oid": format!("sha256:{}", digest(b"gguf").as_str())}}),
        serde_json::json!({"type": "file", "path": "fixture.gguf", "size": 4, "lfs": {"oid": format!("sha256:{}", "f".repeat(64))}}),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = model_destination(&directory);
        let http = Arc::new(MockHttp::new(
            vec![response(serde_json::json!([entry]), None)],
            Vec::new(),
        ));
        let fetcher = HuggingFaceRuntimeModelFetcher::new(
            http.clone(),
            Arc::new(SystemRuntimeModelArtifactIo),
        );
        assert_eq!(
            fetcher
                .fetch(&gguf_artifact(Some(4)), &destination)
                .expect_err("identity"),
            RuntimeError::ModelAcquisitionInvalid
        );
        assert!(http.files.lock().expect("files").is_empty());
    }
}

// Rolls back the complete destination for every download identity and I/O failure.
#[test]
fn download_and_io_failure_matrix_is_transactional() {
    for mutation in ["download", "bytes", "digest", "parent", "seal", "receipt"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = model_destination(&directory);
        let mut download = MockDownload::success(b"gguf");
        match mutation {
            "download" => download.error = Some(RuntimeError::DownloadUnavailable),
            "bytes" => download.reported_bytes = Some(3),
            "digest" => {
                download.reported_sha256 =
                    Some(Sha256Digest::parse(&"f".repeat(64)).expect("digest"))
            }
            _ => {}
        }
        let http = Arc::new(MockHttp::new(
            vec![response(
                serde_json::json!([{"type": "file", "path": "fixture.gguf", "size": 4, "lfs": {"oid": format!("sha256:{}", digest(b"gguf").as_str())}}]),
                None,
            )],
            vec![download],
        ));
        let io = Arc::new(FailingModelIo::new());
        if matches!(mutation, "parent" | "seal" | "receipt") {
            *io.step.lock().expect("step") = Some(mutation);
        }
        let fetcher = HuggingFaceRuntimeModelFetcher::new(http, io.clone());
        assert!(
            fetcher
                .fetch(&gguf_artifact(Some(4)), &destination)
                .is_err(),
            "mutation={mutation}"
        );
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
        assert_eq!(io.clears.load(Ordering::SeqCst), 1);
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = model_destination(&directory);
    let io = Arc::new(FailingModelIo::new());
    *io.step.lock().expect("step") = Some("prepare");
    let fetcher =
        HuggingFaceRuntimeModelFetcher::new(Arc::new(MockHttp::new(Vec::new(), Vec::new())), io);
    assert_eq!(
        fetcher
            .fetch(&snapshot_artifact(), &destination)
            .expect_err("prepare"),
        RuntimeError::ModelAcquisitionUnavailable
    );
}

// Rejects nonempty, symlinked, nonprivate, and unsafe system destinations.
#[test]
fn system_model_io_enforces_private_no_follow_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = model_destination(&directory);
    let io = SystemRuntimeModelArtifactIo;
    io.prepare_destination(&destination).expect("empty");
    fs::write(destination.join("existing"), b"x").expect("file");
    assert!(io.prepare_destination(&destination).is_err());
    io.clear_destination(&destination).expect("clear");
    io.create_parent(&destination, Path::new("nested/deeper"))
        .expect("parents");
    assert!(io
        .create_parent(&destination, Path::new("../escape"))
        .is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("deeper", destination.join("nested/link")).expect("symlink");
        assert!(io.clear_destination(&destination).is_err());
        fs::remove_file(destination.join("nested/link")).expect("remove link");
    }
    io.clear_destination(&destination).expect("final clear");
}

// Delegates each artifact class exactly once through the composed fetcher.
#[test]
fn composed_artifact_fetcher_preserves_independent_mechanism_ownership() {
    struct MockPack(AtomicUsize);
    impl RuntimePackArtifactFetcher for MockPack {
        // Records one runtime-pack delegation.
        fn fetch(
            &self,
            _source: &RuntimeSource,
            _digest: &Sha256Digest,
            _destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct MockModel(AtomicUsize);
    impl RuntimeModelArtifactFetcher for MockModel {
        // Records one model delegation.
        fn fetch(
            &self,
            _artifact: &ModelArtifact,
            _destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct MockEngine(AtomicUsize);
    impl RuntimeEngineArtifactFetcher for MockEngine {
        // Records one Engine delegation.
        fn fetch(
            &self,
            _candidate: &RuntimeCandidate,
            _runtime_root: &Path,
            _destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let pack = Arc::new(MockPack(AtomicUsize::new(0)));
    let model = Arc::new(MockModel(AtomicUsize::new(0)));
    let engine = Arc::new(MockEngine(AtomicUsize::new(0)));
    let fetcher = ComposedRuntimeArtifactFetcher::new(pack.clone(), model.clone(), engine.clone());
    let source = RuntimeSource::parse(&format!(
        "ghcr.io/letsinferlabs/runtime@sha256:{}",
        "3".repeat(64)
    ))
    .expect("source");
    let runtime_digest = Sha256Digest::parse(&"4".repeat(64)).expect("runtime digest");
    fetcher
        .fetch_runtime_pack(&source, &runtime_digest, Path::new("/runtime"))
        .expect("pack");
    fetcher
        .fetch_model_artifact(&snapshot_artifact(), Path::new("/model"))
        .expect("model");
    fetcher
        .fetch_engine_distribution(
            &engine_candidate(),
            Path::new("/runtime"),
            Path::new("/engine"),
        )
        .expect("engine");
    assert_eq!(pack.0.load(Ordering::SeqCst), 1);
    assert_eq!(model.0.load(Ordering::SeqCst), 1);
    assert_eq!(engine.0.load(Ordering::SeqCst), 1);
}
