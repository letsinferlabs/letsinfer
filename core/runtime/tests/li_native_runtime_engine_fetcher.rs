// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use flate2::write::GzEncoder;
use flate2::Compression;
use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture, EngineDistribution,
    EvidenceLabel, LogicalModelName, MemoryTopology, ModelArtifact, ModelArtifactFormat,
    NativeEngineKind, OperatingSystem, PlatformIdentity, RuntimeCandidateId, RuntimeIdentity,
    RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TechnicalName,
};
use li_runtime_manager::{
    ComposedRuntimeEngineFetcher, NativeRuntimeEngineFetcher, NativeRuntimeEngineIo,
    RuntimeAcceleratorVendor, RuntimeCandidate, RuntimeEmbeddedApplicationAcquisition,
    RuntimeEmbeddedApplicationAcquisitionRequest, RuntimeEmbeddedApplicationExecution,
    RuntimeEmbeddedApplicationExecutionRequest, RuntimeEmbeddedApplicationProvider,
    RuntimeEngineArtifactFetcher, RuntimeEngineCommand, RuntimeEngineCommandOutput,
    RuntimeEngineCommandRunner, RuntimeError, RuntimeHttpClient, RuntimeHttpDownload,
    RuntimeHttpRequest, RuntimeTarget, SystemNativeRuntimeEngineIo,
};
use sha2::{Digest, Sha256};

// Returns one canonical SHA-256 for fixture bytes.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Appends one deterministic regular file to a gzip tar builder.
fn append_file(
    builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    mode: u32,
    bytes: &[u8],
) {
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

// Appends one deterministic relative symlink to a gzip tar builder.
fn append_link(builder: &mut tar::Builder<GzEncoder<Vec<u8>>>, path: &str, target: &str) {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).expect("path");
    header.set_size(0);
    header.set_mode(0o777);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name(target).expect("target");
    header.set_cksum();
    builder.append(&header, Cursor::new([])).expect("append");
}

// Returns one deterministic tar.gz archive from regular files and optional links.
fn archive(files: &[(&str, u32, &[u8])], links: &[(&str, &str)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, mode, bytes) in files {
        append_file(&mut builder, path, *mode, bytes);
    }
    for (path, target) in links {
        append_link(&mut builder, path, target);
    }
    let encoder = builder.into_inner().expect("tar");
    encoder.finish().expect("gzip")
}

// Returns one deterministic deflated ZIP archive from regular files.
fn zip_archive(files: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    for (path, mode, bytes) in files {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(*mode);
        writer.start_file(*path, options).expect("start file");
        writer.write_all(bytes).expect("write file");
    }
    writer.finish().expect("finish").into_inner()
}

// Creates one private runtime root with adapter and optional requirements inputs.
fn runtime_root(directory: &tempfile::TempDir, python: bool) -> PathBuf {
    let root = directory.path().join("runtime");
    fs::create_dir(&root).expect("runtime root");
    fs::create_dir(root.join("adapter")).expect("adapter root");
    fs::write(root.join("adapter/engine-adapter"), b"fixture adapter\n").expect("adapter");
    if python {
        fs::create_dir(root.join("engine")).expect("engine root");
        fs::write(
            root.join("engine/requirements.lock"),
            b"fixture==1.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .expect("requirements");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("runtime mode");
        fs::set_permissions(root.join("adapter"), fs::Permissions::from_mode(0o700))
            .expect("adapter mode");
        fs::set_permissions(
            root.join("adapter/engine-adapter"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("entrypoint mode");
        if python {
            fs::set_permissions(root.join("engine"), fs::Permissions::from_mode(0o700))
                .expect("engine mode");
            fs::set_permissions(
                root.join("engine/requirements.lock"),
                fs::Permissions::from_mode(0o644),
            )
            .expect("requirements mode");
        }
    }
    root
}

// Returns one exact model artifact used by native candidate fixtures.
fn model_artifact() -> ModelArtifact {
    ModelArtifact::new(
        ArtifactName::parse("model").expect("name"),
        ArtifactUri::parse("hf://FixtureOrg/FixtureModel").expect("URI"),
        ArtifactRevision::parse(&"1".repeat(40)).expect("revision"),
        ModelArtifactFormat::HuggingFaceSnapshot,
    )
}

// Builds matching runtime.json and persisted native candidate identities.
fn native_fixture(
    directory: &tempfile::TempDir,
    kind: NativeEngineKind,
    archive_bytes: &[u8],
    archive_format: &str,
) -> (RuntimeCandidate, PathBuf) {
    let python = kind == NativeEngineKind::PythonStandalone;
    let root = runtime_root(directory, python);
    let archive = serde_json::json!({
        "url": "https://downloads.example.test/engine.tar.gz",
        "sha256": digest(archive_bytes).as_str(),
        "bytes": archive_bytes.len(),
        "format": archive_format,
        "strip_prefix": if python {"python"} else {"llama"}
    });
    let mut distribution = match kind {
        NativeEngineKind::NativeArchive => serde_json::json!({
            "kind": "native-archive",
            "platform": "macos/arm64",
            "payload_id": format!("sha256:{}", "0".repeat(64)),
            "source_revision": "2".repeat(40),
            "entrypoint": "adapter/engine-adapter",
            "port_count": 2,
            "archive": archive,
            "upstream_executable": "llama-server"
        }),
        NativeEngineKind::PythonStandalone => serde_json::json!({
            "kind": "python-standalone",
            "platform": "macos/arm64",
            "payload_id": format!("sha256:{}", "0".repeat(64)),
            "source_revision": "2".repeat(40),
            "entrypoint": "adapter/engine-adapter",
            "port_count": 2,
            "python": {
                "implementation": "cpython",
                "version": "3.11.16",
                "archive": archive
            },
            "requirements_lock": "engine/requirements.lock"
        }),
        NativeEngineKind::EmbeddedApplication => serde_json::json!({
            "kind": "embedded-application",
            "platform": "macos/arm64",
            "payload_id": format!("sha256:{}", "0".repeat(64)),
            "source_revision": "2".repeat(40),
            "entrypoint": "adapter/engine-adapter",
            "port_count": 1,
            "bundle_id": "ai.letsinfer.fixture",
            "signing_policy": "deployment-managed",
            "minimum_version": "1.0.0",
            "embedded_engine": "fixture"
        }),
    };
    let io = SystemNativeRuntimeEngineIo;
    let payload = io
        .payload_id(
            &root,
            &distribution,
            Path::new("adapter/engine-adapter"),
            python.then_some(Path::new("engine/requirements.lock")),
        )
        .expect("payload");
    distribution["payload_id"] = serde_json::json!(format!("sha256:{}", payload.as_str()));
    let runtime = serde_json::json!({
        "schema_version": 6,
        "id": "fixture--owner--model--target",
        "version": "1.0.0",
        "logical_model": "fixture-model",
        "target": {"id": "target"},
        "engine": {"distribution": distribution}
    });
    fs::write(
        root.join("runtime.json"),
        serde_json::to_vec_pretty(&runtime).expect("runtime"),
    )
    .expect("runtime config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("runtime.json"), fs::Permissions::from_mode(0o644))
            .expect("runtime mode");
    }
    let candidate = RuntimeCandidate::new(
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
            EngineDistribution::native(
                kind,
                PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
                payload,
                ArtifactRevision::parse(&"2".repeat(40)).expect("source revision"),
            ),
            Sha256Digest::parse(&"3".repeat(64)).expect("runtime digest"),
            digest(&fs::read(root.join("runtime.json")).expect("runtime bytes")),
            Sha256Digest::parse(&"4".repeat(64)).expect("execution digest"),
        )
        .expect("runtime"),
        vec![model_artifact()],
        RuntimeTarget::new(
            OperatingSystem::Macos,
            CpuArchitecture::Arm64,
            RuntimeAcceleratorVendor::Apple,
            TechnicalName::parse("apple-silicon").expect("architecture"),
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
    .expect("candidate");
    (candidate, root)
}

// Mocks one streamed native archive download.
struct MockHttp {
    archive: Mutex<Option<Vec<u8>>>,
    reported_bytes: Mutex<Option<u64>>,
    reported_digest: Mutex<Option<Sha256Digest>>,
    error: Mutex<Option<RuntimeError>>,
    requests: AtomicUsize,
}

impl MockHttp {
    // Creates one truthful successful native archive result.
    fn new(archive: &[u8]) -> Self {
        Self {
            archive: Mutex::new(Some(archive.to_vec())),
            reported_bytes: Mutex::new(None),
            reported_digest: Mutex::new(None),
            error: Mutex::new(None),
            requests: AtomicUsize::new(0),
        }
    }
}

impl RuntimeHttpClient for MockHttp {
    // Metadata GET is not part of native archive acquisition.
    fn get(
        &self,
        _request: &RuntimeHttpRequest,
        _maximum_body_bytes: u64,
    ) -> Result<li_runtime_manager::RuntimeHttpResponse, RuntimeError> {
        Err(RuntimeError::DownloadUnavailable)
    }

    // Writes the configured archive and returns its measured identity.
    fn download(
        &self,
        request: &RuntimeHttpRequest,
        destination: &Path,
        _maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpDownload, RuntimeError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.error.lock().expect("error").take() {
            return Err(error);
        }
        let archive = self
            .archive
            .lock()
            .expect("archive")
            .take()
            .ok_or(RuntimeError::DownloadUnavailable)?;
        fs::write(destination, &archive).map_err(|_| RuntimeError::DownloadUnavailable)?;
        RuntimeHttpDownload::new(
            200,
            request.url().to_string(),
            BTreeMap::new(),
            self.reported_bytes
                .lock()
                .expect("bytes")
                .unwrap_or(archive.len() as u64),
            self.reported_digest
                .lock()
                .expect("digest")
                .clone()
                .unwrap_or_else(|| digest(&archive)),
            false,
        )
    }
}

// Mocks ordered CPython version and pip process results.
struct MockRunner {
    outputs: Mutex<VecDeque<Result<RuntimeEngineCommandOutput, RuntimeError>>>,
    commands: Mutex<Vec<RuntimeEngineCommand>>,
}

impl MockRunner {
    // Creates one ordered native process fixture.
    fn new(outputs: Vec<RuntimeEngineCommandOutput>) -> Self {
        Self {
            outputs: Mutex::new(outputs.into_iter().map(Ok).collect()),
            commands: Mutex::new(Vec::new()),
        }
    }
}

impl RuntimeEngineCommandRunner for MockRunner {
    // Returns the next configured native process result.
    fn run(
        &self,
        command: &RuntimeEngineCommand,
        _maximum_stdout_bytes: usize,
    ) -> Result<RuntimeEngineCommandOutput, RuntimeError> {
        self.commands
            .lock()
            .expect("commands")
            .push(command.clone());
        self.outputs
            .lock()
            .expect("outputs")
            .pop_front()
            .unwrap_or(Err(RuntimeError::EngineAcquisitionUnavailable))
    }
}

// Wraps real native Engine I/O and fails one named boundary.
struct FailingIo {
    system: SystemNativeRuntimeEngineIo,
    step: Mutex<Option<&'static str>>,
    clears: AtomicUsize,
}

impl FailingIo {
    // Creates one real-I/O wrapper with no configured failure.
    fn new() -> Self {
        Self {
            system: SystemNativeRuntimeEngineIo,
            step: Mutex::new(None),
            clears: AtomicUsize::new(0),
        }
    }

    // Returns whether one exact I/O boundary is configured to fail.
    fn fails(&self, step: &'static str) -> bool {
        self.step.lock().expect("step").as_ref() == Some(&step)
    }
}

impl NativeRuntimeEngineIo for FailingIo {
    // Prepares one destination or returns the configured failure.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        if self.fails("prepare") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.prepare_destination(destination)
    }

    // Reads runtime configuration or returns the configured failure.
    fn read_runtime_config(&self, runtime_root: &Path) -> Result<Vec<u8>, RuntimeError> {
        if self.fails("config") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.read_runtime_config(runtime_root)
    }

    // Calculates payload identity or returns the configured failure.
    fn payload_id(
        &self,
        runtime_root: &Path,
        distribution: &serde_json::Value,
        entrypoint: &Path,
        requirements_lock: Option<&Path>,
    ) -> Result<Sha256Digest, RuntimeError> {
        if self.fails("payload") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system
            .payload_id(runtime_root, distribution, entrypoint, requirements_lock)
    }

    // Creates one directory or returns the configured failure.
    fn create_directory(&self, path: &Path) -> Result<(), RuntimeError> {
        if self.fails("directory") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.create_directory(path)
    }

    // Extracts one archive or returns the configured failure.
    fn extract_archive(
        &self,
        archive: &Path,
        destination: &Path,
        format: &str,
        strip_prefix: &Path,
    ) -> Result<(), RuntimeError> {
        if self.fails("extract") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system
            .extract_archive(archive, destination, format, strip_prefix)
    }

    // Removes one archive or returns the configured failure.
    fn remove_archive(&self, archive: &Path) -> Result<(), RuntimeError> {
        if self.fails("remove") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.remove_archive(archive)
    }

    // Validates one executable or returns the configured failure.
    fn validate_executable(&self, executable: &Path) -> Result<(), RuntimeError> {
        if self.fails("executable") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.validate_executable(executable)
    }

    // Calculates one tree identity or returns the configured failure.
    fn tree_sha256(&self, destination: &Path) -> Result<Sha256Digest, RuntimeError> {
        if self.fails("tree") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.tree_sha256(destination)
    }

    // Writes one receipt or returns the configured failure.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError> {
        if self.fails("receipt") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.write_receipt(destination, receipt)
    }

    // Writes one embedded app receipt or returns the configured failure.
    fn write_embedded_application_receipt(
        &self,
        destination: &Path,
        receipt: &[u8],
    ) -> Result<(), RuntimeError> {
        if self.fails("embedded_receipt") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system
            .write_embedded_application_receipt(destination, receipt)
    }

    // Clears one failed acquisition or returns the configured failure.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        self.clears.fetch_add(1, Ordering::SeqCst);
        if self.fails("clear") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.clear_destination(destination)
    }
}

// Mocks the independently supervised application without replacing RuntimeManager logic.
struct MockEmbeddedApplication {
    calls: AtomicUsize,
    mismatch: bool,
    unavailable: bool,
}

impl MockEmbeddedApplication {
    // Creates one deterministic app provider for the selected acquisition outcome.
    fn new(mismatch: bool, unavailable: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mismatch,
            unavailable,
        }
    }
}

impl RuntimeEmbeddedApplicationProvider for MockEmbeddedApplication {
    // Returns the exact requested application identity unless the fixture selects one failure.
    fn acquire(
        &self,
        request: &RuntimeEmbeddedApplicationAcquisitionRequest,
    ) -> Result<RuntimeEmbeddedApplicationAcquisition, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.unavailable {
            return Err(RuntimeError::EmbeddedApplicationUnavailable);
        }
        RuntimeEmbeddedApplicationAcquisition::new(
            request.bundle_id().to_string(),
            request.embedded_engine().clone(),
            if self.mismatch {
                Sha256Digest::parse(&"f".repeat(64)).expect("mismatch")
            } else {
                request.payload_id().clone()
            },
            RuntimeVersion::parse("1.0.0").expect("application version"),
        )
    }

    // Execution is outside this acquisition-focused provider matrix.
    fn execute(
        &self,
        _request: &RuntimeEmbeddedApplicationExecutionRequest,
    ) -> Result<RuntimeEmbeddedApplicationExecution, RuntimeError> {
        Err(RuntimeError::EmbeddedApplicationUnavailable)
    }
}

// Creates one empty owner-only native Engine destination.
fn destination(directory: &tempfile::TempDir) -> PathBuf {
    let destination = directory.path().join("native-engine");
    fs::create_dir(&destination).expect("destination");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    destination
}

// Materializes one exact native archive Engine and resolves links into regular files.
#[test]
fn native_archive_materialization_verifies_payload_executable_tree_and_receipt() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(
        &[("llama/llama-server", 0o755, b"native engine")],
        &[("llama/llama-alias", "llama-server")],
    );
    let (candidate, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::NativeArchive,
        &archive,
        "tar.gz",
    );
    let destination = destination(&directory);
    let http = Arc::new(MockHttp::new(&archive));
    let runner = Arc::new(MockRunner::new(Vec::new()));
    let fetcher = NativeRuntimeEngineFetcher::new(
        http.clone(),
        runner.clone(),
        Arc::new(SystemNativeRuntimeEngineIo),
    );
    fetcher
        .fetch(&candidate, &runtime_root, &destination)
        .expect("acquire");
    assert_eq!(
        fs::read(destination.join("upstream/llama-server")).expect("engine"),
        b"native engine"
    );
    assert_eq!(
        fs::read(destination.join("upstream/llama-alias")).expect("alias"),
        b"native engine"
    );
    assert!(destination
        .join("li_native_engine_receipt_v1.json")
        .is_file());
    assert_eq!(http.requests.load(Ordering::SeqCst), 1);
    assert!(runner.commands.lock().expect("commands").is_empty());
}

// Materializes one qualified ZIP native archive through the same closed payload contract.
#[test]
fn zip_native_archive_materialization_is_safe_and_verified() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = zip_archive(&[("llama/llama-server", 0o755, b"zip engine")]);
    let (candidate, runtime_root) =
        native_fixture(&directory, NativeEngineKind::NativeArchive, &archive, "zip");
    let destination = destination(&directory);
    let fetcher = NativeRuntimeEngineFetcher::new(
        Arc::new(MockHttp::new(&archive)),
        Arc::new(MockRunner::new(Vec::new())),
        Arc::new(SystemNativeRuntimeEngineIo),
    );
    fetcher
        .fetch(&candidate, &runtime_root, &destination)
        .expect("acquire ZIP");
    assert_eq!(
        fs::read(destination.join("upstream/llama-server")).expect("engine"),
        b"zip engine"
    );
    assert!(destination
        .join("li_native_engine_receipt_v1.json")
        .is_file());
}

// Materializes exact CPython, verifies its version, and installs one hash-locked closure.
#[test]
fn python_standalone_materialization_uses_fixed_version_and_pip_argv() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(
        &[
            ("python/bin/python3", 0o755, b"python"),
            ("python/lib/runtime", 0o644, b"library"),
        ],
        &[],
    );
    let (candidate, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::PythonStandalone,
        &archive,
        "tar.gz",
    );
    let destination = destination(&directory);
    let runner = Arc::new(MockRunner::new(vec![
        RuntimeEngineCommandOutput::new(0, b"3.11.16\n".to_vec()),
        RuntimeEngineCommandOutput::new(0, Vec::new()),
    ]));
    let fetcher = NativeRuntimeEngineFetcher::new(
        Arc::new(MockHttp::new(&archive)),
        runner.clone(),
        Arc::new(SystemNativeRuntimeEngineIo),
    );
    fetcher
        .fetch(&candidate, &runtime_root, &destination)
        .expect("acquire");
    let commands = runner.commands.lock().expect("commands");
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].arguments()[0], "-c");
    assert_eq!(&commands[1].arguments()[..3], ["-m", "pip", "install"]);
    assert!(commands[1]
        .arguments()
        .iter()
        .any(|value| value == "--require-hashes"));
    assert!(commands[1]
        .arguments()
        .iter()
        .any(|value| value.ends_with("engine/requirements.lock")));
    assert!(destination.join("python/bin/python3").is_file());
    assert!(destination.join("site-packages").is_dir());
}

// Rejects compact/full payload mismatch before any archive download.
#[test]
fn payload_identity_mismatch_fails_before_network_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(&[("llama/llama-server", 0o755, b"engine")], &[]);
    let (mut candidate, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::NativeArchive,
        &archive,
        "tar.gz",
    );
    let original = candidate.clone();
    candidate = RuntimeCandidate::new(
        original.logical_model().clone(),
        RuntimeIdentity::new(
            original.runtime().candidate_id().clone(),
            original.runtime().version().clone(),
            original.runtime().target_id().clone(),
            original.runtime().source().clone(),
            EngineDistribution::native(
                NativeEngineKind::NativeArchive,
                PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
                Sha256Digest::parse(&"f".repeat(64)).expect("wrong payload"),
                ArtifactRevision::parse(&"2".repeat(40)).expect("source revision"),
            ),
            original.runtime().runtime_digest().clone(),
            original.runtime().manifest_digest().clone(),
            original.runtime().execution_contract_digest().clone(),
        )
        .expect("runtime"),
        original.artifacts().to_vec(),
        original.target().clone(),
        original.evidence_label(),
        2,
        false,
        false,
    )
    .expect("candidate");
    let http = Arc::new(MockHttp::new(&archive));
    let fetcher = NativeRuntimeEngineFetcher::new(
        http.clone(),
        Arc::new(MockRunner::new(Vec::new())),
        Arc::new(SystemNativeRuntimeEngineIo),
    );
    assert_eq!(
        fetcher
            .fetch(&candidate, &runtime_root, &destination(&directory))
            .expect_err("payload"),
        RuntimeError::EngineAcquisitionInvalid
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}

// Rejects every native candidate identity and unsupported platform before network execution.
#[test]
fn native_identity_and_platform_mutation_matrix_fails_before_download() {
    for mutation in [
        "candidate",
        "version",
        "logical_model",
        "target",
        "platform",
        "source_revision",
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive(&[("llama/llama-server", 0o755, b"engine")], &[]);
        let (candidate, runtime_root) = native_fixture(
            &directory,
            NativeEngineKind::NativeArchive,
            &archive,
            "tar.gz",
        );
        let path = runtime_root.join("runtime.json");
        let mut runtime: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("runtime")).expect("JSON");
        match mutation {
            "candidate" => runtime["id"] = serde_json::json!("fixture--wrong--model--target"),
            "version" => runtime["version"] = serde_json::json!("2.0.0"),
            "logical_model" => runtime["logical_model"] = serde_json::json!("wrong-model"),
            "target" => runtime["target"]["id"] = serde_json::json!("wrong-target"),
            "platform" => {
                runtime["engine"]["distribution"]["platform"] = serde_json::json!("linux/arm64")
            }
            "source_revision" => {
                runtime["engine"]["distribution"]["source_revision"] =
                    serde_json::json!("private-secret-marker")
            }
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&runtime).expect("runtime bytes"))
            .expect("mutated runtime");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("runtime mode");
        }
        let http = Arc::new(MockHttp::new(&archive));
        let error = NativeRuntimeEngineFetcher::new(
            http.clone(),
            Arc::new(MockRunner::new(Vec::new())),
            Arc::new(SystemNativeRuntimeEngineIo),
        )
        .fetch(&candidate, &runtime_root, &destination(&directory))
        .expect_err("identity mutation");
        assert_eq!(error, RuntimeError::EngineAcquisitionInvalid);
        assert_eq!(http.requests.load(Ordering::SeqCst), 0);
        assert!(!format!("{error:?} {error}").contains("private-secret-marker"));
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(&[("llama/llama-server", 0o755, b"engine")], &[]);
    let (macos, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::NativeArchive,
        &archive,
        "tar.gz",
    );
    let linux = RuntimeCandidate::new(
        macos.logical_model().clone(),
        macos.runtime().clone(),
        macos.artifacts().to_vec(),
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
        .expect("Linux target"),
        macos.evidence_label(),
        2,
        false,
        false,
    )
    .expect("Linux candidate");
    let http = Arc::new(MockHttp::new(&archive));
    assert_eq!(
        NativeRuntimeEngineFetcher::new(
            http.clone(),
            Arc::new(MockRunner::new(Vec::new())),
            Arc::new(SystemNativeRuntimeEngineIo),
        )
        .fetch(&linux, &runtime_root, &destination(&directory))
        .expect_err("unsupported native platform"),
        RuntimeError::EngineAcquisitionInvalid
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}

// Rejects archive transport, size, digest, format, extraction, and executable failures.
#[test]
fn native_archive_failure_matrix_is_transactional() {
    for mutation in [
        "download",
        "bytes",
        "digest",
        "zip",
        "extract",
        "executable",
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive(&[("llama/llama-server", 0o755, b"engine")], &[]);
        let (candidate, runtime_root) = native_fixture(
            &directory,
            NativeEngineKind::NativeArchive,
            &archive,
            if mutation == "zip" { "zip" } else { "tar.gz" },
        );
        let destination = destination(&directory);
        let http = Arc::new(MockHttp::new(&archive));
        match mutation {
            "download" => {
                *http.error.lock().expect("error") = Some(RuntimeError::DownloadUnavailable)
            }
            "bytes" => *http.reported_bytes.lock().expect("bytes") = Some(1),
            "digest" => {
                *http.reported_digest.lock().expect("digest") =
                    Some(Sha256Digest::parse(&"f".repeat(64)).expect("digest"))
            }
            _ => {}
        }
        let io = Arc::new(FailingIo::new());
        if matches!(mutation, "extract" | "executable") {
            *io.step.lock().expect("step") = Some(mutation);
        }
        let fetcher = NativeRuntimeEngineFetcher::new(
            http,
            Arc::new(MockRunner::new(Vec::new())),
            io.clone(),
        );
        assert!(fetcher
            .fetch(&candidate, &runtime_root, &destination)
            .is_err());
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
        assert_eq!(io.clears.load(Ordering::SeqCst), 1);
    }
}

// Rejects CPython version and pip failures while removing the complete staged payload.
#[test]
fn python_process_failure_matrix_is_transactional() {
    for outputs in [
        vec![RuntimeEngineCommandOutput::new(0, b"3.12.0\n".to_vec())],
        vec![RuntimeEngineCommandOutput::new(1, Vec::new())],
        vec![
            RuntimeEngineCommandOutput::new(0, b"3.11.16\n".to_vec()),
            RuntimeEngineCommandOutput::new(1, Vec::new()),
        ],
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive(&[("python/bin/python3", 0o755, b"python")], &[]);
        let (candidate, runtime_root) = native_fixture(
            &directory,
            NativeEngineKind::PythonStandalone,
            &archive,
            "tar.gz",
        );
        let destination = destination(&directory);
        let fetcher = NativeRuntimeEngineFetcher::new(
            Arc::new(MockHttp::new(&archive)),
            Arc::new(MockRunner::new(outputs)),
            Arc::new(SystemNativeRuntimeEngineIo),
        );
        assert!(fetcher
            .fetch(&candidate, &runtime_root, &destination)
            .is_err());
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
    }
}

// Rejects embedded acquisition when no app provider exists and never downloads a host fallback.
#[test]
fn embedded_application_has_no_hidden_host_materialization_fallback() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(&[("unused/file", 0o644, b"unused")], &[]);
    let (candidate, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::EmbeddedApplication,
        &archive,
        "tar.gz",
    );
    let http = Arc::new(MockHttp::new(&archive));
    let fetcher = NativeRuntimeEngineFetcher::new(
        http.clone(),
        Arc::new(MockRunner::new(Vec::new())),
        Arc::new(SystemNativeRuntimeEngineIo),
    );
    assert_eq!(
        fetcher
            .fetch(&candidate, &runtime_root, &destination(&directory))
            .expect_err("embedded"),
        RuntimeError::EmbeddedApplicationUnavailable
    );
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
}

// Records one exact app-owned acquisition while leaving host payload materialization empty.
#[test]
fn embedded_application_acquisition_uses_only_the_explicit_app_handoff() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(&[("unused/file", 0o644, b"unused")], &[]);
    let (candidate, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::EmbeddedApplication,
        &archive,
        "tar.gz",
    );
    let http = Arc::new(MockHttp::new(&archive));
    let application = Arc::new(MockEmbeddedApplication::new(false, false));
    let destination = destination(&directory);
    NativeRuntimeEngineFetcher::new(
        http.clone(),
        Arc::new(MockRunner::new(Vec::new())),
        Arc::new(SystemNativeRuntimeEngineIo),
    )
    .with_embedded_application_provider(application.clone())
    .fetch(&candidate, &runtime_root, &destination)
    .expect("embedded acquisition");
    assert_eq!(application.calls.load(Ordering::SeqCst), 1);
    assert_eq!(http.requests.load(Ordering::SeqCst), 0);
    assert!(destination
        .join("li_runtime_embedded_application_receipt_v1.json")
        .is_file());
    assert!(destination
        .join("li_native_engine_receipt_v1.json")
        .is_file());
}

// Rejects unavailable and mismatched application results while cleaning every staged receipt.
#[test]
fn embedded_application_failure_matrix_is_transactional() {
    for (mismatch, unavailable) in [(false, true), (true, false)] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive(&[("unused/file", 0o644, b"unused")], &[]);
        let (candidate, runtime_root) = native_fixture(
            &directory,
            NativeEngineKind::EmbeddedApplication,
            &archive,
            "tar.gz",
        );
        let destination = destination(&directory);
        let application = Arc::new(MockEmbeddedApplication::new(mismatch, unavailable));
        let result = NativeRuntimeEngineFetcher::new(
            Arc::new(MockHttp::new(&archive)),
            Arc::new(MockRunner::new(Vec::new())),
            Arc::new(SystemNativeRuntimeEngineIo),
        )
        .with_embedded_application_provider(application)
        .fetch(&candidate, &runtime_root, &destination);
        assert!(result.is_err());
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
    }
}

// Exercises failure at every injected native filesystem boundary with cleanup attempts.
#[test]
fn native_io_failure_matrix_covers_all_materialization_exits() {
    for step in [
        "prepare",
        "config",
        "payload",
        "directory",
        "remove",
        "tree",
        "receipt",
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive(&[("llama/llama-server", 0o755, b"engine")], &[]);
        let (candidate, runtime_root) = native_fixture(
            &directory,
            NativeEngineKind::NativeArchive,
            &archive,
            "tar.gz",
        );
        let io = Arc::new(FailingIo::new());
        *io.step.lock().expect("step") = Some(step);
        let fetcher = NativeRuntimeEngineFetcher::new(
            Arc::new(MockHttp::new(&archive)),
            Arc::new(MockRunner::new(Vec::new())),
            io.clone(),
        );
        assert!(
            fetcher
                .fetch(&candidate, &runtime_root, &destination(&directory))
                .is_err(),
            "step={step}"
        );
        if !matches!(step, "prepare" | "config" | "payload") {
            assert_eq!(io.clears.load(Ordering::SeqCst), 1);
        }
    }
}

// Rejects link cycles and path traversal while resolving valid links as regular copies.
#[test]
fn system_extractor_rejects_unsafe_link_and_path_contracts() {
    let io = SystemNativeRuntimeEngineIo;
    for archive in [
        archive(
            &[("root/file", 0o644, b"file")],
            &[("root/a", "b"), ("root/b", "a")],
        ),
        archive(&[("other/file", 0o644, b"outside")], &[]),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = destination(&directory);
        let archive_path = destination.join("archive");
        fs::write(&archive_path, archive).expect("archive");
        let extraction = destination.join("extracted");
        io.create_directory(&extraction).expect("extraction");
        assert!(io
            .extract_archive(&archive_path, &extraction, "tar.gz", Path::new("root"))
            .is_err());
        io.clear_destination(&destination).expect("clear");
    }
}

// Routes OCI and native candidates to exactly one independently injected provider.
#[test]
fn composed_engine_fetcher_selects_one_closed_distribution_mechanism() {
    struct MockEngine(AtomicUsize);
    impl RuntimeEngineArtifactFetcher for MockEngine {
        // Records one exact Engine mechanism delegation.
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
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = archive(&[("llama/llama-server", 0o755, b"engine")], &[]);
    let (native, runtime_root) = native_fixture(
        &directory,
        NativeEngineKind::NativeArchive,
        &archive,
        "tar.gz",
    );
    let oci = {
        let original = native.clone();
        RuntimeCandidate::new(
            original.logical_model().clone(),
            RuntimeIdentity::new(
                original.runtime().candidate_id().clone(),
                original.runtime().version().clone(),
                original.runtime().target_id().clone(),
                original.runtime().source().clone(),
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
                original.runtime().runtime_digest().clone(),
                original.runtime().manifest_digest().clone(),
                original.runtime().execution_contract_digest().clone(),
            )
            .expect("runtime"),
            original.artifacts().to_vec(),
            original.target().clone(),
            original.evidence_label(),
            2,
            false,
            false,
        )
        .expect("candidate")
    };
    let oci_provider = Arc::new(MockEngine(AtomicUsize::new(0)));
    let native_provider = Arc::new(MockEngine(AtomicUsize::new(0)));
    let provider = ComposedRuntimeEngineFetcher::new(oci_provider.clone(), native_provider.clone());
    provider
        .fetch(&oci, &runtime_root, Path::new("/engine"))
        .expect("OCI");
    provider
        .fetch(&native, &runtime_root, Path::new("/engine"))
        .expect("native");
    assert_eq!(oci_provider.0.load(Ordering::SeqCst), 1);
    assert_eq!(native_provider.0.load(Ordering::SeqCst), 1);
}
