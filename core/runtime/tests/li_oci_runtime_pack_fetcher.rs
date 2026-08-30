// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{RuntimeSource, Sha256Digest};
use li_runtime_manager::{
    OciRuntimePackFetcher, RuntimeError, RuntimeHttpClient, RuntimeHttpDownload,
    RuntimeHttpRequest, RuntimeHttpResponse, RuntimePackArtifactFetcher, RuntimePackArtifactIo,
    SystemRuntimePackArtifactIo,
};
use sha2::{Digest, Sha256};

const PACK_MEDIA_TYPE: &str = "application/vnd.letsinfer.runtime.v6+tar";

// Returns one canonical SHA-256 for fixture bytes.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns Python-compatible canonical JSON bytes.
fn canonical(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("canonical JSON");
    bytes.push(b'\n');
    bytes
}

// Appends one deterministic regular file to a tar archive.
fn append_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).expect("path");
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder.append(&header, Cursor::new(bytes)).expect("append");
}

// Returns one deterministic runtime archive and its descriptor identity.
fn pack_fixture() -> (Vec<u8>, Sha256Digest) {
    let runtime = canonical(&serde_json::json!({
        "schema_version": 6,
        "id": "fixture--owner--model--target",
        "version": "1.0.0",
        "logical_model": "fixture-model",
        "engine": {"id": "fixture"},
        "target": {"id": "target"}
    }));
    let adapter = b"#!/bin/sh\nexit 0\n".to_vec();
    let descriptor = serde_json::json!({
        "artifact_schema_version": 6,
        "media_type": PACK_MEDIA_TYPE,
        "runtime_sha256": digest(&runtime).as_str(),
        "candidate": {
            "id": "fixture--owner--model--target",
            "version": "1.0.0",
            "logical_model": "fixture-model",
            "engine": "fixture",
            "target": "target"
        },
        "files": [
            {"path": "runtime.json", "bytes": runtime.len(), "mode": 420, "sha256": digest(&runtime).as_str()},
            {"path": "adapter/engine-adapter", "bytes": adapter.len(), "mode": 493, "sha256": digest(&adapter).as_str()}
        ]
    });
    let descriptor_bytes = canonical(&descriptor);
    let descriptor_digest = digest(&descriptor_bytes);
    let mut builder = tar::Builder::new(Vec::new());
    append_file(
        &mut builder,
        "letsinfer-runtime.json",
        0o644,
        &descriptor_bytes,
    );
    append_file(&mut builder, "runtime.json", 0o644, &runtime);
    append_file(&mut builder, "adapter/engine-adapter", 0o755, &adapter);
    let bytes = builder.into_inner().expect("archive");
    (bytes, descriptor_digest)
}

// Returns one exact OCI manifest and its digest-pinned source identity.
fn manifest_fixture(archive: &[u8]) -> (Vec<u8>, RuntimeSource) {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{
            "mediaType": PACK_MEDIA_TYPE,
            "digest": format!("sha256:{}", digest(archive).as_str()),
            "size": archive.len()
        }]
    }))
    .expect("manifest");
    let source = RuntimeSource::parse(&format!(
        "registry.example.test/org/runtime@sha256:{}",
        digest(&manifest).as_str()
    ))
    .expect("source");
    (manifest, source)
}

// Creates one deterministic HTTP response with normalized headers.
fn response(
    status: u16,
    final_url: &str,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
) -> RuntimeHttpResponse {
    RuntimeHttpResponse::new(status, final_url.to_string(), headers, body, false).expect("response")
}

// Configures one deterministic OCI layer download.
struct MockDownload {
    archive: Vec<u8>,
    bytes: Option<u64>,
    digest: Option<Sha256Digest>,
    error: Option<RuntimeError>,
}

impl MockDownload {
    // Creates one truthful successful layer download.
    fn success(archive: &[u8]) -> Self {
        Self {
            archive: archive.to_vec(),
            bytes: None,
            digest: None,
            error: None,
        }
    }
}

// Mocks registry metadata, HEAD, and streamed layer operations in exact order.
struct MockHttp {
    gets: Mutex<VecDeque<Result<RuntimeHttpResponse, RuntimeError>>>,
    heads: Mutex<VecDeque<Result<RuntimeHttpResponse, RuntimeError>>>,
    download: Mutex<Option<MockDownload>>,
    get_requests: Mutex<Vec<(String, bool)>>,
    head_requests: Mutex<Vec<(String, bool)>>,
    download_requests: Mutex<Vec<(String, bool)>>,
}

impl MockHttp {
    // Creates one ordered registry protocol fixture.
    fn new(
        gets: Vec<RuntimeHttpResponse>,
        heads: Vec<RuntimeHttpResponse>,
        download: MockDownload,
    ) -> Self {
        Self {
            gets: Mutex::new(gets.into_iter().map(Ok).collect()),
            heads: Mutex::new(heads.into_iter().map(Ok).collect()),
            download: Mutex::new(Some(download)),
            get_requests: Mutex::new(Vec::new()),
            head_requests: Mutex::new(Vec::new()),
            download_requests: Mutex::new(Vec::new()),
        }
    }
}

impl RuntimeHttpClient for MockHttp {
    // Returns the next ordered registry metadata response.
    fn get(
        &self,
        request: &RuntimeHttpRequest,
        _maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpResponse, RuntimeError> {
        self.get_requests
            .lock()
            .expect("GET requests")
            .push((request.url().to_string(), request.has_bearer_token()));
        self.gets
            .lock()
            .expect("GET responses")
            .pop_front()
            .unwrap_or(Err(RuntimeError::DownloadUnavailable))
    }

    // Returns the next ordered registry blob metadata response.
    fn head(&self, request: &RuntimeHttpRequest) -> Result<RuntimeHttpResponse, RuntimeError> {
        self.head_requests
            .lock()
            .expect("HEAD requests")
            .push((request.url().to_string(), request.has_bearer_token()));
        self.heads
            .lock()
            .expect("HEAD responses")
            .pop_front()
            .unwrap_or(Err(RuntimeError::DownloadUnavailable))
    }

    // Writes the exact configured archive and returns its measured identity.
    fn download(
        &self,
        request: &RuntimeHttpRequest,
        destination: &Path,
        _maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpDownload, RuntimeError> {
        self.download_requests
            .lock()
            .expect("download requests")
            .push((request.url().to_string(), request.has_bearer_token()));
        let value = self
            .download
            .lock()
            .expect("download")
            .take()
            .ok_or(RuntimeError::DownloadUnavailable)?;
        if let Some(error) = value.error {
            return Err(error);
        }
        fs::write(destination, &value.archive).map_err(|_| RuntimeError::DownloadUnavailable)?;
        RuntimeHttpDownload::new(
            200,
            request.url().to_string(),
            BTreeMap::new(),
            value.bytes.unwrap_or(value.archive.len() as u64),
            value.digest.unwrap_or_else(|| digest(&value.archive)),
            request.allows_loopback_http(),
        )
    }
}

// Wraps real pack I/O and fails one named boundary.
struct FailingPackIo {
    system: SystemRuntimePackArtifactIo,
    step: Mutex<Option<&'static str>>,
    clears: AtomicUsize,
}

impl FailingPackIo {
    // Creates one real-I/O wrapper with no configured failure.
    fn new() -> Self {
        Self {
            system: SystemRuntimePackArtifactIo,
            step: Mutex::new(None),
            clears: AtomicUsize::new(0),
        }
    }

    // Returns whether one exact pack-I/O boundary is configured to fail.
    fn fails(&self, step: &'static str) -> bool {
        self.step.lock().expect("step").as_ref() == Some(&step)
    }
}

impl RuntimePackArtifactIo for FailingPackIo {
    // Prepares a destination or returns the configured failure.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        if self.fails("prepare") {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        self.system.prepare_destination(destination)
    }

    // Extracts an archive or returns the configured failure.
    fn extract_archive(&self, archive: &Path, destination: &Path) -> Result<(), RuntimeError> {
        if self.fails("extract") {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        self.system.extract_archive(archive, destination)
    }

    // Removes an archive or returns the configured failure.
    fn remove_archive(&self, archive: &Path) -> Result<(), RuntimeError> {
        if self.fails("remove") {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        self.system.remove_archive(archive)
    }

    // Verifies a descriptor or returns the configured failure.
    fn verify_descriptor(
        &self,
        destination: &Path,
        expected_digest: &Sha256Digest,
    ) -> Result<(), RuntimeError> {
        if self.fails("verify") {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        self.system.verify_descriptor(destination, expected_digest)
    }

    // Returns verified documents or fails the same descriptor boundary.
    fn verified_documents(
        &self,
        destination: &Path,
    ) -> Result<li_runtime_manager::RuntimePackDocuments, RuntimeError> {
        if self.fails("verify") {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        self.system.verified_documents(destination)
    }

    // Clears a failed destination or returns the configured failure.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        self.clears.fetch_add(1, Ordering::SeqCst);
        if self.fails("clear") {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        self.system.clear_destination(destination)
    }
}

// Creates one empty owner-only runtime-pack destination.
fn pack_destination(directory: &tempfile::TempDir) -> PathBuf {
    let destination = directory.path().join("runtime");
    fs::create_dir(&destination).expect("destination");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    destination
}

// Returns ordinary manifest and blob responses for one pack fixture.
fn ordinary_responses(
    manifest: &[u8],
    archive: &[u8],
) -> (RuntimeHttpResponse, RuntimeHttpResponse) {
    (
        response(
            200,
            "https://registry.example.test/v2/org/runtime/manifests/fixture",
            BTreeMap::new(),
            manifest.to_vec(),
        ),
        response(
            200,
            "https://registry.example.test/v2/org/runtime/blobs/fixture",
            BTreeMap::from([("content-length".to_string(), archive.len().to_string())]),
            Vec::new(),
        ),
    )
}

// Acquires, extracts, and verifies one anonymous single-layer OCI runtime pack.
#[test]
fn anonymous_oci_pack_acquisition_verifies_complete_descriptor_closure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let (archive, runtime_digest) = pack_fixture();
    let (manifest, source) = manifest_fixture(&archive);
    let (manifest_response, head_response) = ordinary_responses(&manifest, &archive);
    let http = Arc::new(MockHttp::new(
        vec![manifest_response],
        vec![head_response],
        MockDownload::success(&archive),
    ));
    let fetcher = OciRuntimePackFetcher::new(http.clone(), Arc::new(SystemRuntimePackArtifactIo));
    fetcher
        .fetch(&source, &runtime_digest, &destination)
        .expect("acquire");
    assert!(destination.join("letsinfer-runtime.json").is_file());
    assert!(destination.join("runtime.json").is_file());
    assert!(destination.join("adapter/engine-adapter").is_file());
    assert!(!destination.join(".li_runtime_archive").exists());
    assert_eq!(http.get_requests.lock().expect("GET").len(), 1);
    assert_eq!(http.head_requests.lock().expect("HEAD").len(), 1);
    assert_eq!(http.download_requests.lock().expect("download").len(), 1);
}

// Discovers exact candidate documents only after the same complete OCI closure verifies.
#[test]
fn anonymous_oci_pack_hydration_returns_verified_descriptor_and_runtime_bytes() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let (archive, runtime_digest) = pack_fixture();
    let (manifest, source) = manifest_fixture(&archive);
    let (manifest_response, head_response) = ordinary_responses(&manifest, &archive);
    let http = Arc::new(MockHttp::new(
        vec![manifest_response],
        vec![head_response],
        MockDownload::success(&archive),
    ));
    let fetcher = OciRuntimePackFetcher::new(http, Arc::new(SystemRuntimePackArtifactIo));
    let documents = fetcher
        .documents(&source, &destination)
        .expect("verified documents");
    assert_eq!(documents.descriptor_digest(), &runtime_digest);
    assert!(documents.descriptor().starts_with(b"{"));
    assert!(documents.runtime().starts_with(b"{"));
    fetcher.clear(&destination).expect("clear");
    assert!(destination
        .read_dir()
        .expect("destination")
        .next()
        .is_none());
}

// Resolves one public bearer challenge and keeps the token scoped to registry requests.
#[test]
fn bearer_authentication_is_pull_scoped_and_redacted_from_protocol_results() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let (archive, runtime_digest) = pack_fixture();
    let (manifest, source) = manifest_fixture(&archive);
    let challenge = "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:org/runtime:pull\"";
    let unauthorized = response(
        401,
        "https://registry.example.test/v2/org/runtime/manifests/fixture",
        BTreeMap::from([("www-authenticate".to_string(), challenge.to_string())]),
        Vec::new(),
    );
    let token = response(
        200,
        "https://auth.example.test/token",
        BTreeMap::new(),
        br#"{"token":"fixture-bearer-token"}"#.to_vec(),
    );
    let (manifest_response, head_response) = ordinary_responses(&manifest, &archive);
    let http = Arc::new(MockHttp::new(
        vec![unauthorized, token, manifest_response],
        vec![head_response],
        MockDownload::success(&archive),
    ));
    let fetcher = OciRuntimePackFetcher::new(http.clone(), Arc::new(SystemRuntimePackArtifactIo));
    fetcher
        .fetch(&source, &runtime_digest, &destination)
        .expect("acquire");
    let gets = http.get_requests.lock().expect("GET requests");
    assert_eq!(
        gets.iter().map(|request| request.1).collect::<Vec<_>>(),
        [false, false, true]
    );
    assert!(http.head_requests.lock().expect("HEAD")[0].1);
    assert!(http.download_requests.lock().expect("download")[0].1);
}

// Refreshes one rejected bearer exactly once while preserving the finite protocol bound.
#[test]
fn bearer_authentication_permits_one_bounded_token_refresh() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let (archive, runtime_digest) = pack_fixture();
    let (manifest, source) = manifest_fixture(&archive);
    let challenge = "Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\",scope=\"repository:org/runtime:pull\"";
    let unauthorized = || {
        response(
            401,
            "https://registry.example.test/v2/org/runtime/manifests/fixture",
            BTreeMap::from([("www-authenticate".to_string(), challenge.to_string())]),
            Vec::new(),
        )
    };
    let token = |value: &str| {
        response(
            200,
            "https://auth.example.test/token",
            BTreeMap::new(),
            format!("{{\"token\":\"{value}\"}}").into_bytes(),
        )
    };
    let (manifest_response, head_response) = ordinary_responses(&manifest, &archive);
    let http = Arc::new(MockHttp::new(
        vec![
            unauthorized(),
            token("expired-token"),
            unauthorized(),
            token("fresh-token"),
            manifest_response,
        ],
        vec![head_response],
        MockDownload::success(&archive),
    ));
    let fetcher = OciRuntimePackFetcher::new(http.clone(), Arc::new(SystemRuntimePackArtifactIo));
    fetcher
        .fetch(&source, &runtime_digest, &destination)
        .expect("acquire after refresh");
    assert_eq!(
        http.get_requests
            .lock()
            .expect("GET requests")
            .iter()
            .map(|request| request.1)
            .collect::<Vec<_>>(),
        [false, false, true, false, true]
    );
}

// Drops bearer authorization before following a blob redirect to a signed CDN URL.
#[test]
fn blob_redirect_never_forwards_registry_bearer_token() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let (archive, runtime_digest) = pack_fixture();
    let (manifest, source) = manifest_fixture(&archive);
    let (manifest_response, _head) = ordinary_responses(&manifest, &archive);
    let redirect = response(
        307,
        "https://registry.example.test/v2/org/runtime/blobs/fixture",
        BTreeMap::from([(
            "location".to_string(),
            "https://cdn.example.test/runtime.letsinfer".to_string(),
        )]),
        Vec::new(),
    );
    let cdn = response(
        200,
        "https://cdn.example.test/runtime.letsinfer",
        BTreeMap::from([("content-length".to_string(), archive.len().to_string())]),
        Vec::new(),
    );
    let challenge = response(
        401,
        "https://registry.example.test/v2/org/runtime/manifests/fixture",
        BTreeMap::from([(
            "www-authenticate".to_string(),
            "Bearer realm=\"https://auth.example.test/token\"".to_string(),
        )]),
        Vec::new(),
    );
    let token = response(
        200,
        "https://auth.example.test/token",
        BTreeMap::new(),
        br#"{"access_token":"fixture-token"}"#.to_vec(),
    );
    let http = Arc::new(MockHttp::new(
        vec![challenge, token, manifest_response],
        vec![redirect, cdn],
        MockDownload::success(&archive),
    ));
    let fetcher = OciRuntimePackFetcher::new(http.clone(), Arc::new(SystemRuntimePackArtifactIo));
    fetcher
        .fetch(&source, &runtime_digest, &destination)
        .expect("acquire");
    let heads = http.head_requests.lock().expect("HEAD");
    assert_eq!(
        heads.iter().map(|request| request.1).collect::<Vec<_>>(),
        [true, false]
    );
    assert!(!http.download_requests.lock().expect("download")[0].1);
}

// Rejects mutable references and malformed manifest identities before layer activation.
#[test]
fn source_and_manifest_mutation_matrix_fails_closed() {
    let (archive, runtime_digest) = pack_fixture();
    let base_manifest: serde_json::Value =
        serde_json::from_slice(&manifest_fixture(&archive).0).expect("manifest");
    let mutations: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        (
            "schema",
            Box::new(|value| value["schemaVersion"] = serde_json::json!(1)),
        ),
        (
            "media",
            Box::new(|value| value["mediaType"] = serde_json::json!("unsupported")),
        ),
        (
            "layers",
            Box::new(|value| value["layers"] = serde_json::json!([])),
        ),
        (
            "layer media",
            Box::new(|value| value["layers"][0]["mediaType"] = serde_json::json!("unsupported")),
        ),
        (
            "layer digest",
            Box::new(|value| value["layers"][0]["digest"] = serde_json::json!("wrong")),
        ),
        (
            "layer size",
            Box::new(|value| value["layers"][0]["size"] = serde_json::json!(0)),
        ),
    ];
    for (name, mutate) in mutations {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = pack_destination(&directory);
        let mut value = base_manifest.clone();
        mutate(&mut value);
        let manifest = serde_json::to_vec(&value).expect("manifest");
        let source = RuntimeSource::parse(&format!(
            "registry.example.test/org/runtime@sha256:{}",
            digest(&manifest).as_str()
        ))
        .expect("source");
        let head = ordinary_responses(&manifest, &archive).1;
        let fetcher = OciRuntimePackFetcher::new(
            Arc::new(MockHttp::new(
                vec![response(
                    200,
                    "https://registry.example.test/manifest",
                    BTreeMap::new(),
                    manifest,
                )],
                vec![head],
                MockDownload::success(&archive),
            )),
            Arc::new(SystemRuntimePackArtifactIo),
        );
        assert_eq!(
            fetcher
                .fetch(&source, &runtime_digest, &destination)
                .expect_err("manifest"),
            RuntimeError::RuntimePackAcquisitionInvalid,
            "mutation={name}"
        );
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let mutable = RuntimeSource::parse(&format!("letsinfer-object:sha256:{}", "f".repeat(64)))
        .expect("local source");
    let fetcher = OciRuntimePackFetcher::new(
        Arc::new(MockHttp::new(
            Vec::new(),
            Vec::new(),
            MockDownload::success(&archive),
        )),
        Arc::new(SystemRuntimePackArtifactIo),
    );
    assert_eq!(
        fetcher
            .fetch(&mutable, &runtime_digest, &destination)
            .expect_err("non-OCI"),
        RuntimeError::RuntimePackAcquisitionInvalid
    );
}

// Rejects malformed challenges and token responses without ever requesting a blob.
#[test]
fn bearer_challenge_mutation_matrix_fails_closed() {
    let (archive, runtime_digest) = pack_fixture();
    let (manifest, source) = manifest_fixture(&archive);
    for challenge in [
        "Basic realm=\"https://auth.example.test/token\"",
        "Bearer service=\"registry\"",
        "Bearer realm=\"http://auth.example.test/token\"",
        "Bearer realm=\"https://user@auth.example.test/token\"",
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = pack_destination(&directory);
        let unauthorized = response(
            401,
            "https://registry.example.test/manifest",
            BTreeMap::from([("www-authenticate".to_string(), challenge.to_string())]),
            Vec::new(),
        );
        let fetcher = OciRuntimePackFetcher::new(
            Arc::new(MockHttp::new(
                vec![unauthorized],
                Vec::new(),
                MockDownload::success(&archive),
            )),
            Arc::new(SystemRuntimePackArtifactIo),
        );
        assert!(fetcher
            .fetch(&source, &runtime_digest, &destination)
            .is_err());
    }
    for body in [
        b"not json".to_vec(),
        br#"{}"#.to_vec(),
        br#"{"token":"two words"}"#.to_vec(),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = pack_destination(&directory);
        let unauthorized = response(
            401,
            "https://registry.example.test/manifest",
            BTreeMap::from([(
                "www-authenticate".to_string(),
                "Bearer realm=\"https://auth.example.test/token\"".to_string(),
            )]),
            Vec::new(),
        );
        let token = response(
            200,
            "https://auth.example.test/token",
            BTreeMap::new(),
            body,
        );
        let fetcher = OciRuntimePackFetcher::new(
            Arc::new(MockHttp::new(
                vec![unauthorized, token],
                Vec::new(),
                MockDownload::success(&archive),
            )),
            Arc::new(SystemRuntimePackArtifactIo),
        );
        assert!(fetcher
            .fetch(&source, &runtime_digest, &destination)
            .is_err());
    }
    let _ = manifest;
}

// Rejects blob status, length, download, size, and digest divergence transactionally.
#[test]
fn blob_failure_matrix_never_leaves_partial_pack_material() {
    for mutation in ["head", "length", "download", "bytes", "digest"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = pack_destination(&directory);
        let (archive, runtime_digest) = pack_fixture();
        let (manifest, source) = manifest_fixture(&archive);
        let mut head = ordinary_responses(&manifest, &archive).1;
        let mut download = MockDownload::success(&archive);
        match mutation {
            "head" => {
                head = response(
                    503,
                    "https://registry.example.test/blob",
                    BTreeMap::new(),
                    Vec::new(),
                )
            }
            "length" => {
                head = response(
                    200,
                    "https://registry.example.test/blob",
                    BTreeMap::from([("content-length".to_string(), "1".to_string())]),
                    Vec::new(),
                )
            }
            "download" => download.error = Some(RuntimeError::DownloadUnavailable),
            "bytes" => download.bytes = Some(1),
            "digest" => {
                download.digest = Some(Sha256Digest::parse(&"f".repeat(64)).expect("digest"))
            }
            _ => unreachable!(),
        }
        let fetcher = OciRuntimePackFetcher::new(
            Arc::new(MockHttp::new(
                vec![ordinary_responses(&manifest, &archive).0],
                vec![head],
                download,
            )),
            Arc::new(SystemRuntimePackArtifactIo),
        );
        assert!(fetcher
            .fetch(&source, &runtime_digest, &destination)
            .is_err());
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
    }
}

// Exercises failure at every injected pack filesystem boundary with cleanup attempts.
#[test]
fn pack_io_failure_matrix_is_transactional() {
    for step in ["prepare", "extract", "remove", "verify"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = pack_destination(&directory);
        let (archive, runtime_digest) = pack_fixture();
        let (manifest, source) = manifest_fixture(&archive);
        let (manifest_response, head_response) = ordinary_responses(&manifest, &archive);
        let io = Arc::new(FailingPackIo::new());
        *io.step.lock().expect("step") = Some(step);
        let fetcher = OciRuntimePackFetcher::new(
            Arc::new(MockHttp::new(
                vec![manifest_response],
                vec![head_response],
                MockDownload::success(&archive),
            )),
            io.clone(),
        );
        assert!(fetcher
            .fetch(&source, &runtime_digest, &destination)
            .is_err());
        if step != "prepare" {
            assert_eq!(io.clears.load(Ordering::SeqCst), 1);
        }
    }
}

// Rejects corrupt archives and descriptor/file divergence through the real verifier.
#[test]
fn system_pack_io_rejects_archive_and_descriptor_corruption() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = pack_destination(&directory);
    let archive = destination.join("archive");
    fs::write(&archive, b"not a tar").expect("archive");
    let io = SystemRuntimePackArtifactIo;
    assert_eq!(
        io.extract_archive(&archive, &destination)
            .expect_err("corrupt archive"),
        RuntimeError::RuntimePackAcquisitionInvalid
    );
    io.clear_destination(&destination).expect("clear");

    let (pack, runtime_digest) = pack_fixture();
    fs::write(&archive, &pack).expect("archive");
    io.extract_archive(&archive, &destination).expect("extract");
    io.remove_archive(&archive).expect("remove archive");
    fs::write(destination.join("runtime.json"), b"corrupt").expect("corrupt");
    assert_eq!(
        io.verify_descriptor(&destination, &runtime_digest)
            .expect_err("corrupt file"),
        RuntimeError::RuntimePackAcquisitionInvalid
    );
}
