// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture, EngineDistribution,
    EvidenceLabel, LogicalModelName, MemoryTopology, ModelArtifact, ModelArtifactFormat,
    NativeEngineKind, OperatingSystem, PlatformIdentity, RuntimeCandidateId, RuntimeIdentity,
    RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TechnicalName,
};
use li_runtime_manager::{
    FilesystemRuntimeArtifactVerifier, NativeRuntimeEngineIo, RuntimeAcceleratorVendor,
    RuntimeArtifactClosureIo, RuntimeArtifactVerifier, RuntimeCandidate, RuntimeError,
    RuntimePackArtifactIo, RuntimeTarget, SystemRuntimeArtifactClosureIo,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

// Returns one canonical SHA-256 for fixture bytes.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns one exact model artifact fixture.
fn model_artifact() -> ModelArtifact {
    ModelArtifact::new(
        ArtifactName::parse("model").expect("name"),
        ArtifactUri::parse("hf://FixtureOrg/FixtureModel").expect("URI"),
        ArtifactRevision::parse(&"1".repeat(40)).expect("revision"),
        ModelArtifactFormat::HuggingFaceSnapshot,
    )
}

// Returns one exact OCI candidate fixture.
fn oci_candidate() -> RuntimeCandidate {
    candidate(EngineDistribution::oci(
        RuntimeSource::parse(&format!(
            "ghcr.io/letsinferlabs/engine@sha256:{}",
            "5".repeat(64)
        ))
        .expect("Engine source"),
        Sha256Digest::parse(&"6".repeat(64)).expect("Engine ID"),
        None,
        None,
    ))
}

// Returns one exact native candidate fixture.
fn native_candidate() -> RuntimeCandidate {
    candidate(EngineDistribution::native(
        NativeEngineKind::NativeArchive,
        PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
        Sha256Digest::parse(&"6".repeat(64)).expect("payload"),
        ArtifactRevision::parse(&"7".repeat(40)).expect("source revision"),
    ))
}

// Returns one exact embedded-application candidate fixture.
fn embedded_candidate() -> RuntimeCandidate {
    candidate(EngineDistribution::native(
        NativeEngineKind::EmbeddedApplication,
        PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
        Sha256Digest::parse(&"6".repeat(64)).expect("payload"),
        ArtifactRevision::parse(&"7".repeat(40)).expect("source revision"),
    ))
}

// Creates one candidate around an exact Engine distribution.
fn candidate(distribution: EngineDistribution) -> RuntimeCandidate {
    let native = matches!(distribution, EngineDistribution::Native { .. });
    RuntimeCandidate::new(
        LogicalModelName::parse("fixture-model").expect("model"),
        RuntimeIdentity::new(
            RuntimeCandidateId::parse("fixture--owner--model--target").expect("candidate"),
            RuntimeVersion::parse("1.0.0").expect("version"),
            TargetId::parse("target").expect("target"),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/runtime@sha256:{}",
                "2".repeat(64)
            ))
            .expect("runtime source"),
            distribution,
            Sha256Digest::parse(&"2".repeat(64)).expect("runtime digest"),
            Sha256Digest::parse(&"3".repeat(64)).expect("manifest digest"),
            Sha256Digest::parse(&"4".repeat(64)).expect("execution digest"),
        )
        .expect("runtime"),
        vec![model_artifact()],
        RuntimeTarget::new(
            if native {
                OperatingSystem::Macos
            } else {
                OperatingSystem::Linux
            },
            CpuArchitecture::Arm64,
            if native {
                RuntimeAcceleratorVendor::Apple
            } else {
                RuntimeAcceleratorVendor::Nvidia
            },
            TechnicalName::parse(if native { "apple-silicon" } else { "sm_121" })
                .expect("architecture"),
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

// Mocks runtime-pack verification and records exact invocation.
struct MockPackIo {
    verifies: AtomicUsize,
    should_fail: Mutex<bool>,
}

impl MockPackIo {
    // Creates one successful pack verifier mock.
    fn new() -> Self {
        Self {
            verifies: AtomicUsize::new(0),
            should_fail: Mutex::new(false),
        }
    }
}

impl RuntimePackArtifactIo for MockPackIo {
    // Rejects unused acquisition preparation.
    fn prepare_destination(&self, _destination: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused archive extraction.
    fn extract_archive(&self, _archive: &Path, _destination: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused archive removal.
    fn remove_archive(&self, _archive: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Records one exact descriptor verification or configured failure.
    fn verify_descriptor(
        &self,
        _destination: &Path,
        _expected_digest: &Sha256Digest,
    ) -> Result<(), RuntimeError> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        if *self.should_fail.lock().expect("failure") {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }

    // Rejects document hydration because this verifier-only mock materializes no pack documents.
    fn verified_documents(
        &self,
        _destination: &Path,
    ) -> Result<li_runtime_manager::RuntimePackDocuments, RuntimeError> {
        Err(RuntimeError::RuntimePackAcquisitionUnavailable)
    }

    // Rejects unused destination cleanup.
    fn clear_destination(&self, _destination: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }
}

// Mocks only native configuration, payload, and tree operations used during verification.
struct MockNativeIo {
    runtime: Vec<u8>,
    payload: Sha256Digest,
    tree: Sha256Digest,
    reads: AtomicUsize,
    trees: AtomicUsize,
}

impl MockNativeIo {
    // Creates one deterministic native verifier mock.
    fn new(runtime: Vec<u8>) -> Self {
        Self {
            runtime,
            payload: Sha256Digest::parse(&"6".repeat(64)).expect("payload"),
            tree: Sha256Digest::parse(&"8".repeat(64)).expect("tree"),
            reads: AtomicUsize::new(0),
            trees: AtomicUsize::new(0),
        }
    }
}

impl NativeRuntimeEngineIo for MockNativeIo {
    // Rejects unused acquisition preparation.
    fn prepare_destination(&self, _destination: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Returns the configured installed runtime configuration.
    fn read_runtime_config(&self, _runtime_root: &Path) -> Result<Vec<u8>, RuntimeError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.runtime.clone())
    }

    // Returns the configured recomputed payload identity.
    fn payload_id(
        &self,
        _runtime_root: &Path,
        _distribution: &serde_json::Value,
        _entrypoint: &Path,
        _requirements_lock: Option<&Path>,
    ) -> Result<Sha256Digest, RuntimeError> {
        Ok(self.payload.clone())
    }

    // Rejects unused directory creation.
    fn create_directory(&self, _path: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused extraction.
    fn extract_archive(
        &self,
        _archive: &Path,
        _destination: &Path,
        _format: &str,
        _strip_prefix: &Path,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused archive removal.
    fn remove_archive(&self, _archive: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused executable validation.
    fn validate_executable(&self, _executable: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Returns the configured recomputed native tree identity.
    fn tree_sha256(&self, _destination: &Path) -> Result<Sha256Digest, RuntimeError> {
        self.trees.fetch_add(1, Ordering::SeqCst);
        Ok(self.tree.clone())
    }

    // Rejects unused receipt writing.
    fn write_receipt(&self, _destination: &Path, _receipt: &[u8]) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused embedded application receipt writing.
    fn write_embedded_application_receipt(
        &self,
        _destination: &Path,
        _receipt: &[u8],
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }

    // Rejects unused cleanup.
    fn clear_destination(&self, _destination: &Path) -> Result<(), RuntimeError> {
        Err(RuntimeError::ArtifactUnavailable)
    }
}

// Mocks closed layout/model/Engine verification and records every call.
struct MockClosureIo {
    fail: Mutex<Option<&'static str>>,
    layouts: AtomicUsize,
    models: AtomicUsize,
    engines: AtomicUsize,
    observed_native_distribution: Mutex<bool>,
}

impl MockClosureIo {
    // Creates one successful closure verifier mock.
    fn new() -> Self {
        Self {
            fail: Mutex::new(None),
            layouts: AtomicUsize::new(0),
            models: AtomicUsize::new(0),
            engines: AtomicUsize::new(0),
            observed_native_distribution: Mutex::new(false),
        }
    }

    // Returns whether one exact verifier boundary is configured to fail.
    fn fails(&self, step: &'static str) -> bool {
        self.fail.lock().expect("failure").as_ref() == Some(&step)
    }
}

impl RuntimeArtifactClosureIo for MockClosureIo {
    // Records one closed layout verification.
    fn verify_layout(
        &self,
        _candidate: &RuntimeCandidate,
        _root: &Path,
    ) -> Result<(), RuntimeError> {
        self.layouts.fetch_add(1, Ordering::SeqCst);
        if self.fails("layout") {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }

    // Records one exact model verification.
    fn verify_model(&self, _artifact: &ModelArtifact, _root: &Path) -> Result<(), RuntimeError> {
        self.models.fetch_add(1, Ordering::SeqCst);
        if self.fails("model") {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }

    // Records one exact Engine verification and native distribution handoff.
    fn verify_engine(
        &self,
        _candidate: &RuntimeCandidate,
        _root: &Path,
        _native_tree_sha256: Option<&Sha256Digest>,
        native_distribution: Option<&serde_json::Value>,
    ) -> Result<(), RuntimeError> {
        self.engines.fetch_add(1, Ordering::SeqCst);
        *self
            .observed_native_distribution
            .lock()
            .expect("native distribution") = native_distribution.is_some();
        if self.fails("engine") {
            Err(RuntimeError::ArtifactUnavailable)
        } else {
            Ok(())
        }
    }
}

// Verifies one complete OCI closure through every independently injected boundary.
#[test]
fn verifier_orders_layout_pack_models_and_engine_for_oci() {
    let pack = Arc::new(MockPackIo::new());
    let native = Arc::new(MockNativeIo::new(Vec::new()));
    let closure = Arc::new(MockClosureIo::new());
    let verifier =
        FilesystemRuntimeArtifactVerifier::new(pack.clone(), native.clone(), closure.clone());
    verifier
        .verify(&oci_candidate(), Path::new("/installation"))
        .expect("verify");
    assert_eq!(closure.layouts.load(Ordering::SeqCst), 1);
    assert_eq!(pack.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(closure.models.load(Ordering::SeqCst), 1);
    assert_eq!(closure.engines.load(Ordering::SeqCst), 1);
    assert_eq!(native.reads.load(Ordering::SeqCst), 0);
    assert_eq!(native.trees.load(Ordering::SeqCst), 0);
}

// Recomputes native payload and tree before handing exact distribution to closure validation.
#[test]
fn verifier_recomputes_native_runtime_and_tree_identity() {
    let distribution = serde_json::json!({
        "kind": "native-archive",
        "platform": "macos/arm64",
        "payload_id": format!("sha256:{}", "6".repeat(64)),
        "source_revision": "7".repeat(40),
        "entrypoint": "adapter/engine-adapter",
        "port_count": 2,
        "archive": {},
        "upstream_executable": "engine"
    });
    let runtime = serde_json::to_vec(&serde_json::json!({
        "engine": {"distribution": distribution}
    }))
    .expect("runtime");
    let pack = Arc::new(MockPackIo::new());
    let native = Arc::new(MockNativeIo::new(runtime));
    let closure = Arc::new(MockClosureIo::new());
    let verifier = FilesystemRuntimeArtifactVerifier::new(pack, native.clone(), closure.clone());
    verifier
        .verify(&native_candidate(), Path::new("/installation"))
        .expect("verify");
    assert_eq!(native.reads.load(Ordering::SeqCst), 1);
    assert_eq!(native.trees.load(Ordering::SeqCst), 1);
    assert!(*closure
        .observed_native_distribution
        .lock()
        .expect("distribution"));
}

// Stops at each injected verification boundary without claiming a valid closure.
#[test]
fn verifier_failure_matrix_is_deterministic() {
    for step in ["layout", "pack", "model", "engine"] {
        let pack = Arc::new(MockPackIo::new());
        let native = Arc::new(MockNativeIo::new(Vec::new()));
        let closure = Arc::new(MockClosureIo::new());
        if step == "pack" {
            *pack.should_fail.lock().expect("failure") = true;
        } else {
            *closure.fail.lock().expect("failure") = Some(step);
        }
        let verifier = FilesystemRuntimeArtifactVerifier::new(pack, native, closure);
        assert_eq!(
            verifier
                .verify(&oci_candidate(), Path::new("/installation"))
                .expect_err("failure"),
            RuntimeError::ArtifactUnavailable,
            "step={step}"
        );
    }
}

// Creates one owner-only directory and all missing parents.
fn private_directory(path: &Path) {
    fs::create_dir_all(path).expect("directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
}

// Writes one owner-only exact file.
fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
    }
}

// Verifies real model receipt, file inventory, bytes, modes, and corruption exits.
#[test]
fn system_model_verifier_enforces_complete_offline_receipt() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().join("model");
    private_directory(&root);
    private_directory(&root.join("nested"));
    private_file(&root.join("config.json"), b"{}");
    private_file(&root.join("nested/weights.bin"), b"weights");
    let receipt = serde_json::json!({
        "schema": {"name": "li_model_artifact_receipt", "version": 1},
        "artifact": {
            "name": "model",
            "uri": "hf://FixtureOrg/FixtureModel",
            "revision": "1".repeat(40),
            "format": {"kind": "huggingface-snapshot"}
        },
        "files": [
            {"path": "config.json", "bytes": 2, "sha256": digest(b"{}").as_str()},
            {"path": "nested/weights.bin", "bytes": 7, "sha256": digest(b"weights").as_str()}
        ]
    });
    private_file(
        &root.join("li_model_artifact_receipt_v1.json"),
        &serde_json::to_vec(&receipt).expect("receipt"),
    );
    let verifier = SystemRuntimeArtifactClosureIo;
    verifier
        .verify_model(&model_artifact(), &root)
        .expect("verify");
    fs::write(root.join("nested/weights.bin"), b"corrupt").expect("corrupt");
    assert_eq!(
        verifier
            .verify_model(&model_artifact(), &root)
            .expect_err("corrupt"),
        RuntimeError::ArtifactUnavailable
    );
}

// Verifies real OCI, materialized-native, and embedded-app receipt identity plus tree binding.
#[test]
fn system_engine_verifier_enforces_both_receipt_unions() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let oci_root = directory.path().join("oci");
    private_directory(&oci_root);
    let oci = oci_candidate();
    let EngineDistribution::Oci {
        reference,
        immutable_id,
        ..
    } = oci.runtime().engine_distribution()
    else {
        unreachable!()
    };
    private_file(
        &oci_root.join("li_engine_oci_v1.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema": {"name": "li_engine_oci_receipt", "version": 1},
            "reference": reference.as_str(),
            "immutable_id": format!("sha256:{}", immutable_id.as_str()),
            "platform": "linux/arm64"
        }))
        .expect("receipt"),
    );
    let verifier = SystemRuntimeArtifactClosureIo;
    verifier
        .verify_engine(&oci, &oci_root, None, None)
        .expect("OCI");

    let native_root = directory.path().join("native");
    private_directory(&native_root);
    let native = native_candidate();
    let tree = Sha256Digest::parse(&"8".repeat(64)).expect("tree");
    let distribution = serde_json::json!({
        "kind": "native-archive",
        "platform": "macos/arm64",
        "payload_id": format!("sha256:{}", "6".repeat(64)),
        "source_revision": "7".repeat(40),
        "entrypoint": "adapter/engine-adapter",
        "port_count": 2,
        "archive": {},
        "upstream_executable": "engine"
    });
    private_file(
        &native_root.join("li_native_engine_receipt_v1.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema": {"name": "li_native_engine_receipt", "version": 1},
            "distribution": distribution,
            "tree_sha256": tree.as_str()
        }))
        .expect("receipt"),
    );
    verifier
        .verify_engine(&native, &native_root, Some(&tree), Some(&distribution))
        .expect("native");

    let embedded_root = directory.path().join("embedded");
    private_directory(&embedded_root);
    let embedded = embedded_candidate();
    let embedded_distribution = serde_json::json!({
        "kind": "embedded-application",
        "platform": "macos/arm64",
        "payload_id": format!("sha256:{}", "6".repeat(64)),
        "source_revision": "7".repeat(40),
        "entrypoint": "adapter/engine-adapter",
        "port_count": 1,
        "bundle_id": "ai.letsinfer.fixture",
        "signing_policy": "deployment-managed",
        "minimum_version": "1.0.0",
        "embedded_engine": "fixture"
    });
    let embedded_receipt = serde_json::json!({
        "schema": {"name": "li_runtime_embedded_application_receipt", "version": 1},
        "candidate_id": "fixture--owner--model--target",
        "version": "1.0.0",
        "logical_model": "fixture-model",
        "target_id": "target",
        "runtime_digest": "2".repeat(64),
        "manifest_digest": "3".repeat(64),
        "payload_id": "6".repeat(64),
        "source_revision": "7".repeat(40),
        "bundle_id": "ai.letsinfer.fixture",
        "embedded_engine": "fixture",
        "minimum_version": "1.0.0",
        "application_version": "1.1.0",
        "entrypoint": "adapter/engine-adapter",
        "port_count": 1
    });
    private_file(
        &embedded_root.join("li_runtime_embedded_application_receipt_v1.json"),
        &serde_json::to_vec(&embedded_receipt).expect("receipt"),
    );
    private_file(
        &embedded_root.join("li_native_engine_receipt_v1.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema": {"name": "li_native_engine_receipt", "version": 1},
            "distribution": embedded_distribution,
            "tree_sha256": tree.as_str()
        }))
        .expect("receipt"),
    );
    verifier
        .verify_engine(
            &embedded,
            &embedded_root,
            Some(&tree),
            Some(&embedded_distribution),
        )
        .expect("embedded");
    let mut corrupt_receipt: Value = serde_json::from_slice(
        &fs::read(embedded_root.join("li_runtime_embedded_application_receipt_v1.json"))
            .expect("receipt"),
    )
    .expect("receipt");
    corrupt_receipt["payload_id"] = serde_json::json!("f".repeat(64));
    private_file(
        &embedded_root.join("li_runtime_embedded_application_receipt_v1.json"),
        &serde_json::to_vec(&corrupt_receipt).expect("receipt"),
    );
    assert_eq!(
        verifier
            .verify_engine(
                &embedded,
                &embedded_root,
                Some(&tree),
                Some(&embedded_distribution),
            )
            .expect_err("embedded identity"),
        RuntimeError::ArtifactUnavailable
    );
    let duplicate = serde_json::to_string(&embedded_receipt)
        .expect("receipt")
        .replacen("\"port_count\":1", "\"port_count\":1,\"port_count\":1", 1);
    private_file(
        &embedded_root.join("li_runtime_embedded_application_receipt_v1.json"),
        duplicate.as_bytes(),
    );
    assert_eq!(
        verifier
            .verify_engine(
                &embedded,
                &embedded_root,
                Some(&tree),
                Some(&embedded_distribution),
            )
            .expect_err("duplicate receipt key"),
        RuntimeError::ArtifactUnavailable
    );
}

// Proves the RuntimeManager-owned embedded receipt schema matches its exact producer.
#[test]
fn distributed_embedded_application_receipt_schema_matches_the_producer() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/runtime/li_runtime_embedded_application_receipt_v1.schema.json"
    ))
    .expect("schema");
    assert_eq!(
        schema["properties"]["schema"]["properties"]["name"]["const"],
        "li_runtime_embedded_application_receipt"
    );
    assert_eq!(
        schema["properties"]["schema"]["properties"]["version"]["const"],
        1
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["port_count"]["minimum"], 1);
    assert_eq!(schema["properties"]["port_count"]["maximum"], 4);
}

// Rejects missing, extra, file-shaped, and symlinked installation layout entries.
#[test]
fn system_layout_verifier_requires_closed_three_root_shape() {
    let directory = tempfile::tempdir().expect("temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    }
    for name in ["runtime", "models", "engine", "models/model"] {
        private_directory(&directory.path().join(name));
    }
    let verifier = SystemRuntimeArtifactClosureIo;
    verifier
        .verify_layout(&oci_candidate(), directory.path())
        .expect("layout");
    private_directory(&directory.path().join("foreign"));
    assert!(verifier
        .verify_layout(&oci_candidate(), directory.path())
        .is_err());
    fs::remove_dir(directory.path().join("foreign")).expect("remove");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("model", directory.path().join("models/link")).expect("symlink");
        assert!(verifier
            .verify_layout(&oci_candidate(), directory.path())
            .is_err());
    }
}
