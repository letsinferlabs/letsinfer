// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, EngineDistribution, EntityTimestamps,
    EvidenceLabel, GgufFileIdentity, LogicalModelName, ModelArtifact, ModelArtifactFormat,
    NativeEngineKind, NodeId, PlatformIdentity, RuntimeCandidateId, RuntimeIdentity,
    RuntimeInstallation, RuntimeInstallationId, RuntimeInstallationState, RuntimeSource,
    RuntimeVersion, Sha256Digest, TargetId, TaskId, UnixMilliseconds,
};
use li_runtime_manager::{
    FilesystemRuntimeExecutionManifestProvider, RuntimeError, RuntimeExecutionContainer,
    RuntimeExecutionDistribution, RuntimeExecutionManifest, RuntimeExecutionManifestIo,
    RuntimeExecutionManifestProvider, RuntimeExecutionPlatform, RuntimeExecutionReadiness,
    RuntimeExecutionServing, RuntimeExecutionTask, RuntimeInstallationProvider,
    RuntimeInstallationStore, RuntimeManager, RuntimeTaskLauncher,
    StoredRuntimeInstallationProvider, SystemRuntimeExecutionManifestIo,
    VersionedRuntimeInstallation,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INSTALLATION_ROOT: &str = "/managed/li_runtime_installations";
const CACHE_ROOT: &str = "/managed/li_runtime_cache";

// Returns one complete schema-6 Linux runtime source fixture.
fn linux_value() -> Value {
    json!({
        "schema_version": 6,
        "id": "sglang--radixark--qwen3.8--dgx-spark",
        "version": "1.0.0",
        "logical_model": "qwen3.8",
        "target": {
            "id": "dgx-spark",
            "platform": "linux/arm64",
            "accelerator": {
                "vendor": "nvidia",
                "architecture": "sm_121",
                "count": 1,
                "partitioning": "full-device"
            },
            "memory": {"topology": "unified", "minimum_total_gib": 64},
            "placement": {
                "strategy": "single",
                "node_count": 1,
                "interconnect": {
                    "kind": "any",
                    "rdma_required": false,
                    "minimum_speed_mbps": 0,
                    "minimum_mtu": 0
                }
            }
        },
        "engine": {
            "id": "sglang",
            "protocol": {"version": 2},
            "distribution": {
                "kind": "oci-container",
                "reference": format!("ghcr.io/letsinferlabs/engine-images@sha256:{}", "3".repeat(64)),
                "immutable_id": format!("sha256:{}", "4".repeat(64)),
                "base": format!("docker.io/upstream/engine@sha256:{}", "5".repeat(64)),
                "payload_id": format!("sha256:{}", "6".repeat(64))
            },
            "model_format": "huggingface-snapshot",
            "cache_provider": "fixture-prefix-v1",
            "arguments": ["--context-length", "32768"],
            "environment": {"FIXTURE_MODE": "deterministic"}
        },
        "model": {
            "uri": "hf://RadixArk/Qwen3.8",
            "artifact": "model",
            "acquisition": {"kind": "oci-container", "image": format!("docker.io/upstream/engine@sha256:{}", "5".repeat(64))}
        },
        "artifacts": [{
            "name": "model",
            "uri": "hf://RadixArk/Qwen3.8",
            "format": "huggingface-snapshot",
            "revision": "7".repeat(40)
        }],
        "container": {
            "memory_bytes": 68719476736_u64,
            "shm_bytes": 8589934592_u64,
            "min_available_gib": 64,
            "runtime_min_available_gib": 4,
            "startup_timeout_seconds": 900,
            "cpuset_cpus": "0-7"
        },
        "cache": {
            "provider": "fixture-prefix-v1",
            "persistent": true,
            "prewarm": true,
            "replay_output_policy": "restored-repeat-exact",
            "config": {"ttl_seconds": 60}
        },
        "serving": {
            "max_connections": 128,
            "max_active_requests": 8,
            "max_context_tokens": 32768,
            "gate": null
        },
        "benchmark": {"contract": {
            "schema_version": 8,
            "suite": "letsinfer-code-prose-v1",
            "generator": {"id": "letsinfer-code-prose", "version": 8},
            "domains": ["code"],
            "execution": {
                "isolation": "fresh-context",
                "prefix_state": "shared",
                "samples_per_cell": 1,
                "stream_prefix": "shared-body"
            },
            "tokenizer": {
                "capability": "engine-rendered-chat-count-v1",
                "model_sha256": "1".repeat(64),
                "engine_payload_sha256": "2".repeat(64),
                "render_contract": "openai-chat-user-v1"
            },
            "request": {
                "output_tokens": 8,
                "min_completion_tokens": 1,
                "require_natural_stop": false,
                "temperature": 0,
                "seed": 7
            },
            "short": {
                "domains": ["code", "prose"],
                "prompt_tokens": 256,
                "concurrencies": [1, 2, 4],
                "request": {
                    "output_tokens": 8,
                    "min_completion_tokens": 1,
                    "require_natural_stop": false,
                    "temperature": 0,
                    "seed": 7
                }
            },
            "ttft_cache": {
                "prompt_tokens": 64000,
                "prompt_domain": "code",
                "repetitions": 2,
                "request": {
                    "output_tokens": 1,
                    "min_completion_tokens": 1,
                    "require_natural_stop": false,
                    "temperature": 0,
                    "seed": 7
                }
            },
            "sample_interval_seconds": 1,
            "cases": [
                {"id": "32k", "prompt_tokens": 32768, "concurrencies": [1, 2, 4]},
                {"id": "64k", "prompt_tokens": 65536, "concurrencies": [1, 2]}
            ]
        }}
    })
}

// Returns one complete schema-6 native macOS runtime source fixture.
fn macos_value() -> Value {
    let mut value = linux_value();
    value["id"] = json!("llamacpp--qwen--qwen3-0.6b--macos-apple");
    value["logical_model"] = json!("qwen3-0.6b");
    value["target"]["id"] = json!("macos-apple");
    value["target"]["platform"] = json!("macos/arm64");
    value["target"]["accelerator"]["vendor"] = json!("apple");
    value["target"]["accelerator"]["architecture"] = json!("apple-silicon");
    value["engine"]["id"] = json!("llamacpp");
    value["engine"]["distribution"] = json!({
        "kind": "native-archive",
        "platform": "macos/arm64",
        "payload_id": format!("sha256:{}", "8".repeat(64)),
        "source_revision": "9".repeat(40),
        "entrypoint": "adapter/engine-adapter",
        "port_count": 2,
        "archive": {
            "url": "https://example.invalid/engine.tar.gz",
            "sha256": "a".repeat(64),
            "bytes": 1024,
            "format": "tar.gz",
            "strip_prefix": "engine"
        },
        "upstream_executable": "llama-server"
    });
    value["engine"]["model_format"] = json!("gguf-file");
    value["engine"]["cache_provider"] = json!("llamacpp-memory-v1");
    value["model"] = json!({
        "uri": "hf://Qwen/Qwen3-0.6B-GGUF",
        "artifact": "model",
        "acquisition": {"kind": "huggingface-http", "client": "huggingface-http-v1"}
    });
    value["artifacts"] = json!([{
        "name": "model",
        "uri": "hf://Qwen/Qwen3-0.6B-GGUF",
        "format": "gguf-file",
        "revision": "b".repeat(40),
        "filename": "Qwen3-0.6B-Q8_0.gguf",
        "sha256": "c".repeat(64),
        "bytes": 639446688_u64
    }]);
    value["container"]["shm_bytes"] = json!(0);
    value["container"]
        .as_object_mut()
        .expect("container")
        .remove("cpuset_cpus");
    value["cache"] = json!({
        "provider": "llamacpp-memory-v1",
        "persistent": false,
        "prewarm": false,
        "replay_output_policy": null,
        "config": {}
    });
    value
}

// Returns one parallel contract with manifest and runtime-command tasks.
fn parallel_value() -> Value {
    let mut value = linux_value();
    value["target"]["placement"] = json!({
        "strategy": "parallel",
        "node_count": 2,
        "interconnect": {
            "kind": "connectx",
            "rdma_required": true,
            "minimum_speed_mbps": 100000,
            "minimum_mtu": 1500
        }
    });
    value["orchestration"] = json!({
        "schema_version": 3,
        "failure_policy": "whole-group",
        "endpoint_owner": "task-0",
        "startup_order": [["task-0", "task-1"]],
        "tasks": [
            {
                "task_id": "task-0",
                "launcher": "manifest",
                "environment": {"NCCL_NET": "IB"},
                "port_count": 2,
                "readiness": {"kind": "manifest"}
            },
            {
                "task_id": "task-1",
                "launcher": "runtime-command",
                "command": ["/opt/letsinfer/bin/worker", "serve"],
                "environment": {"NCCL_NET": "IB", "WORKER_MODE": "participant"},
                "port_count": 2,
                "readiness": {
                    "kind": "exec",
                    "command": ["/opt/letsinfer/bin/worker", "ready"],
                    "interval_seconds": 2,
                    "timeout_seconds": 5,
                    "retries": 30
                }
            }
        ]
    });
    value
}

// Serializes one fixture exactly as the file identity consumed by RuntimeManager.
fn manifest_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixture serialization");
    bytes.push(b'\n');
    bytes
}

// Returns the same Python-compatible compact JSON identity used by production parsing.
fn canonical_digest(value: &Value) -> Sha256Digest {
    let mut bytes = serde_json::to_vec(value).expect("canonical JSON");
    bytes.push(b'\n');
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns one canonical SHA-256 digest.
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("digest")
}

// Returns the Python-compatible canonical JSON digest for an execution contract.
fn execution_digest(value: &Value) -> Sha256Digest {
    let subject = value
        .get("orchestration")
        .cloned()
        .unwrap_or_else(|| json!({"contract": "letsinfer-single-task-v1"}));
    let mut bytes = serde_json::to_vec(&subject).expect("canonical fixture");
    bytes.push(b'\n');
    digest(&bytes)
}

// Creates persisted installation state that matches one fixture's immutable identity.
fn installation(value: &Value, state: RuntimeInstallationState) -> RuntimeInstallation {
    let distribution = match value["engine"]["distribution"]["kind"]
        .as_str()
        .expect("distribution kind")
    {
        "oci-container" => EngineDistribution::oci(
            RuntimeSource::parse(
                value["engine"]["distribution"]["reference"]
                    .as_str()
                    .expect("reference"),
            )
            .expect("reference"),
            Sha256Digest::parse(
                value["engine"]["distribution"]["immutable_id"]
                    .as_str()
                    .expect("immutable ID")
                    .trim_start_matches("sha256:"),
            )
            .expect("immutable ID"),
            value["engine"]["distribution"]
                .get("base")
                .and_then(Value::as_str)
                .map(RuntimeSource::parse)
                .transpose()
                .expect("base"),
            value["engine"]["distribution"]
                .get("payload_id")
                .and_then(Value::as_str)
                .map(|value| Sha256Digest::parse(value.trim_start_matches("sha256:")))
                .transpose()
                .expect("payload"),
        ),
        "native-archive" => EngineDistribution::native(
            NativeEngineKind::NativeArchive,
            PlatformIdentity::new(
                li_core_interface::OperatingSystem::Macos,
                li_core_interface::CpuArchitecture::Arm64,
            ),
            Sha256Digest::parse(
                value["engine"]["distribution"]["payload_id"]
                    .as_str()
                    .expect("payload")
                    .trim_start_matches("sha256:"),
            )
            .expect("payload"),
            ArtifactRevision::parse(
                value["engine"]["distribution"]["source_revision"]
                    .as_str()
                    .expect("source revision"),
            )
            .expect("source revision"),
        ),
        _ => panic!("unsupported fixture distribution"),
    };
    let artifacts = value["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|value| {
            let format = if value["format"] == "huggingface-snapshot" {
                ModelArtifactFormat::HuggingFaceSnapshot
            } else {
                ModelArtifactFormat::GgufFile(
                    GgufFileIdentity::new(
                        value["filename"].as_str().expect("filename"),
                        Sha256Digest::parse(value["sha256"].as_str().expect("SHA-256"))
                            .expect("SHA-256"),
                        value.get("bytes").and_then(Value::as_u64),
                    )
                    .expect("GGUF"),
                )
            };
            ModelArtifact::new(
                ArtifactName::parse(value["name"].as_str().expect("name")).expect("name"),
                ArtifactUri::parse(value["uri"].as_str().expect("URI")).expect("URI"),
                ArtifactRevision::parse(value["revision"].as_str().expect("revision"))
                    .expect("revision"),
                format,
            )
        })
        .collect();
    RuntimeInstallation::new(
        RuntimeInstallationId::parse(&"d".repeat(32)).expect("installation"),
        NodeId::parse(&"e".repeat(32)).expect("node"),
        LogicalModelName::parse(value["logical_model"].as_str().expect("model")).expect("model"),
        RuntimeIdentity::new(
            RuntimeCandidateId::parse(value["id"].as_str().expect("candidate")).expect("candidate"),
            RuntimeVersion::parse(value["version"].as_str().expect("version")).expect("version"),
            TargetId::parse(value["target"]["id"].as_str().expect("target")).expect("target"),
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/runtime-artifacts@sha256:{}",
                "1".repeat(64)
            ))
            .expect("runtime source"),
            distribution,
            Sha256Digest::parse(&"1".repeat(64)).expect("runtime digest"),
            digest(&manifest_bytes(value)),
            execution_digest(value),
        )
        .expect("runtime identity"),
        artifacts,
        EvidenceLabel::Unqualified,
        state,
        (state == RuntimeInstallationState::Failed).then(|| {
            li_core_interface::FailureDescription::new(
                li_core_interface::TechnicalName::parse("fixture_failure").expect("code"),
                "Fixture failure",
            )
            .expect("failure")
        }),
        EntityTimestamps::new(UnixMilliseconds::new(1), UnixMilliseconds::new(2))
            .expect("timestamps"),
    )
    .expect("installation")
}

// Supplies one deterministic installation or configured read failure.
struct MockInstallations {
    value: Mutex<Option<RuntimeInstallation>>,
    should_fail: AtomicBool,
}

impl MockInstallations {
    // Creates one deterministic installation provider.
    fn new(value: Option<RuntimeInstallation>) -> Self {
        Self {
            value: Mutex::new(value),
            should_fail: AtomicBool::new(false),
        }
    }
}

impl RuntimeInstallationProvider for MockInstallations {
    // Returns configured state without touching a database.
    fn installation(
        &self,
        _installation_id: &RuntimeInstallationId,
    ) -> Result<Option<RuntimeInstallation>, RuntimeError> {
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(RuntimeError::StoreUnavailable);
        }
        Ok(self.value.lock().expect("installation").clone())
    }
}

// Supplies deterministic manifest bytes and records every native read.
struct MockIo {
    bytes: Mutex<Vec<u8>>,
    should_fail: AtomicBool,
    reads: AtomicUsize,
}

impl MockIo {
    // Creates one deterministic native-I/O fixture.
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Mutex::new(bytes),
            should_fail: AtomicBool::new(false),
            reads: AtomicUsize::new(0),
        }
    }
}

impl RuntimeExecutionManifestIo for MockIo {
    // Returns configured bytes without consulting the host filesystem.
    fn read(&self, _path: &Path, _maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(RuntimeError::ExecutionManifestUnavailable);
        }
        Ok(self.bytes.lock().expect("bytes").clone())
    }
}

// Creates one provider with retained deterministic boundary mocks.
fn provider(
    value: &Value,
    state: RuntimeInstallationState,
) -> (
    FilesystemRuntimeExecutionManifestProvider,
    Arc<MockInstallations>,
    Arc<MockIo>,
) {
    let installations = Arc::new(MockInstallations::new(Some(installation(value, state))));
    let io = Arc::new(MockIo::new(manifest_bytes(value)));
    let provider = FilesystemRuntimeExecutionManifestProvider::new(
        INSTALLATION_ROOT.into(),
        CACHE_ROOT.into(),
        installations.clone(),
        io.clone(),
    )
    .expect("provider");
    (provider, installations, io)
}

// Parses one exact Linux single-task manifest and preserves every typed boundary.
#[test]
fn linux_single_manifest_is_verified_and_typed() {
    let value = linux_value();
    let (provider, _installations, io) = provider(&value, RuntimeInstallationState::Available);
    let manifest = provider
        .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
        .expect("manifest");
    assert_eq!(manifest.platform(), RuntimeExecutionPlatform::LinuxArm64);
    assert_eq!(manifest.logical_model().as_str(), "qwen3.8");
    assert_eq!(manifest.engine_id().as_str(), "sglang");
    assert_eq!(manifest.cache_provider(), "fixture-prefix-v1");
    let RuntimeExecutionDistribution::Oci {
        identity_reference,
        execution_reference,
        ..
    } = manifest.distribution()
    else {
        panic!("expected OCI distribution");
    };
    assert_eq!(execution_reference.as_str(), identity_reference.as_str());
    assert!(execution_reference.local_config_digest().is_none());
    assert_eq!(manifest.engine_arguments(), ["--context-length", "32768"]);
    assert_eq!(
        manifest.engine_environment(),
        [("FIXTURE_MODE".to_string(), "deterministic".to_string())]
    );
    assert!(manifest.has_persistent_cache());
    assert_eq!(manifest.container().memory_bytes(), 68_719_476_736);
    assert_eq!(manifest.container().cpuset(), Some("0-7"));
    assert_eq!(manifest.serving().max_active_requests(), 8);
    assert_eq!(manifest.tasks().len(), 1);
    assert_eq!(manifest.tasks()[0].task_id().as_str(), "task-0");
    assert!(manifest.tasks()[0].is_endpoint_owner());
    assert_eq!(
        manifest.runtime_root(),
        Path::new(INSTALLATION_ROOT)
            .join("d".repeat(32))
            .join("runtime")
    );
    assert_eq!(manifest.cache_root(), Path::new(CACHE_ROOT));
    let benchmark = manifest.benchmark().expect("benchmark contract");
    assert_eq!(
        benchmark.contract_sha256(),
        &canonical_digest(&value["benchmark"]["contract"])
    );
    assert_eq!(
        benchmark.target_contract_sha256(),
        &canonical_digest(&value["target"])
    );
    let mut contract_document =
        serde_json::to_vec(&value["benchmark"]["contract"]).expect("contract JSON");
    contract_document.push(b'\n');
    assert_eq!(benchmark.document(), contract_document.as_slice());
    assert_eq!(
        benchmark
            .declared_cells()
            .iter()
            .map(|cell| cell.as_str())
            .collect::<Vec<_>>(),
        vec![
            "short-code-c1",
            "short-prose-c1",
            "short-code-c2",
            "short-prose-c2",
            "short-code-c4",
            "short-prose-c4",
            "ttftcold-code-c1",
            "ttftwarm-code-c1",
            "32k-code-c1",
            "32k-code-c2",
            "32k-code-c4",
            "64k-code-c1",
            "64k-code-c2",
        ]
    );
    assert_eq!(io.reads.load(Ordering::SeqCst), 1);
}

// Rejects malformed current benchmark cells and labels older contracts as unsupported.
#[test]
fn benchmark_contract_projection_is_exact_and_fail_closed() {
    let mut unsupported = linux_value();
    unsupported["benchmark"]["contract"]["schema_version"] = json!(7);
    let (unsupported_provider, _, _) = provider(&unsupported, RuntimeInstallationState::Available);
    assert!(unsupported_provider
        .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
        .expect("unsupported contract remains an executable runtime")
        .benchmark()
        .is_none());

    let mut empty_domains = linux_value();
    empty_domains["benchmark"]["contract"]["domains"] = json!([]);
    let (empty_provider, _, _) = provider(&empty_domains, RuntimeInstallationState::Available);
    assert_eq!(
        empty_provider
            .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
            .unwrap_err(),
        RuntimeError::ExecutionManifestInvalid,
    );

    let mut duplicate = linux_value();
    duplicate["benchmark"]["contract"]["cases"][0]["concurrencies"] = json!([1, 1]);
    let (duplicate_provider, _, _) = provider(&duplicate, RuntimeInstallationState::Available);
    assert_eq!(
        duplicate_provider
            .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
            .unwrap_err(),
        RuntimeError::ExecutionManifestInvalid,
    );
}

// Parses native distribution paths without making them platform discoveries.
#[test]
fn macos_native_manifest_preserves_exact_execution_paths() {
    let value = macos_value();
    let (provider, _, _) = provider(&value, RuntimeInstallationState::Available);
    let manifest = provider
        .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
        .expect("manifest");
    assert_eq!(manifest.platform(), RuntimeExecutionPlatform::MacosArm64);
    assert!(!manifest.has_persistent_cache());
    assert_eq!(manifest.container().shared_memory_bytes(), 0);
    assert_eq!(manifest.tasks()[0].port_count(), 2);
    assert!(matches!(
        manifest.distribution(),
        RuntimeExecutionDistribution::NativeArchive {
            entrypoint,
            upstream_executable,
            port_count: 2
        } if entrypoint == Path::new("adapter/engine-adapter")
            && upstream_executable == Path::new("llama-server")
    ));
}

// Preserves opaque parallel tasks, endpoint ownership, readiness, and concurrent phases.
#[test]
fn parallel_manifest_preserves_every_runtime_owned_task_field() {
    let value = parallel_value();
    let (provider, _, _) = provider(&value, RuntimeInstallationState::Available);
    let manifest = provider
        .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
        .expect("manifest");
    assert_eq!(manifest.tasks().len(), 2);
    assert_eq!(manifest.startup_order()[0].len(), 2);
    assert!(matches!(
        manifest.tasks()[1].launcher(),
        RuntimeTaskLauncher::RuntimeCommand(arguments)
            if arguments == &["/opt/letsinfer/bin/worker", "serve"]
    ));
    assert!(matches!(
        manifest.tasks()[1].readiness(),
        RuntimeExecutionReadiness::Exec { retries: 30, .. }
    ));
    assert_eq!(manifest.tasks()[1].environment().len(), 2);
    assert!(!manifest.tasks()[1].is_endpoint_owner());
}

// Returns identical typed values across repeated reads of unchanged exact bytes.
#[test]
fn repeated_manifest_reads_are_deterministic() {
    let value = parallel_value();
    let (provider, _, io) = provider(&value, RuntimeInstallationState::Available);
    let identity = RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity");
    assert_eq!(
        provider.manifest(&identity).expect("first"),
        provider.manifest(&identity).expect("second")
    );
    assert_eq!(io.reads.load(Ordering::SeqCst), 2);
}

// Requires an explicitly configured execution provider on RuntimeManager.
#[test]
fn runtime_manager_forwards_only_the_narrow_execution_capability() {
    struct EmptyCatalog;
    impl li_runtime_manager::RuntimeCatalogProvider for EmptyCatalog {
        // Returns no candidates because this test exercises installed execution only.
        fn candidates(
            &self,
            _model: &LogicalModelName,
        ) -> Result<Vec<li_runtime_manager::RuntimeCandidate>, RuntimeError> {
            Ok(Vec::new())
        }
    }
    let value = linux_value();
    let (execution, _, _) = provider(&value, RuntimeInstallationState::Available);
    let identity = RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity");
    let unavailable = RuntimeManager::new(Arc::new(EmptyCatalog));
    assert_eq!(
        unavailable
            .execution_manifest(&identity)
            .expect_err("capability must be explicit"),
        RuntimeError::ExecutionUnavailable
    );
    let manager =
        RuntimeManager::new(Arc::new(EmptyCatalog)).with_execution_provider(Arc::new(execution));
    assert_eq!(
        manager
            .execution_manifest(&identity)
            .expect("execution")
            .installation_id(),
        &identity
    );
}

// Rejects absent, non-Available, and mismatched persisted installation states.
#[test]
fn persisted_installation_state_fails_closed_before_native_reads() {
    let value = linux_value();
    for state in [
        RuntimeInstallationState::Staging,
        RuntimeInstallationState::Removing,
        RuntimeInstallationState::Removed,
        RuntimeInstallationState::Failed,
    ] {
        let (provider, _, io) = provider(&value, state);
        assert_eq!(
            provider
                .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
                .expect_err("state must fail"),
            RuntimeError::ExecutionManifestInvalid
        );
        assert_eq!(io.reads.load(Ordering::SeqCst), 0);
    }
    let installations = Arc::new(MockInstallations::new(None));
    let io = Arc::new(MockIo::new(manifest_bytes(&value)));
    let provider = FilesystemRuntimeExecutionManifestProvider::new(
        INSTALLATION_ROOT.into(),
        CACHE_ROOT.into(),
        installations,
        io.clone(),
    )
    .expect("provider");
    assert_eq!(
        provider
            .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
            .expect_err("missing installation"),
        RuntimeError::InstallationNotFound
    );
    assert_eq!(io.reads.load(Ordering::SeqCst), 0);
}

// Propagates store and native-I/O failure without parsing or fabricating a result.
#[test]
fn injected_store_and_io_failures_are_distinct_and_deterministic() {
    let value = linux_value();
    let (provider, installations, io) = provider(&value, RuntimeInstallationState::Available);
    let identity = RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity");
    installations.should_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        provider.manifest(&identity).expect_err("store failure"),
        RuntimeError::StoreUnavailable
    );
    installations.should_fail.store(false, Ordering::SeqCst);
    io.should_fail.store(true, Ordering::SeqCst);
    assert_eq!(
        provider.manifest(&identity).expect_err("I/O failure"),
        RuntimeError::ExecutionManifestUnavailable
    );
}

// Rejects empty, oversized, and digest-divergent bytes even from a faulty injected reader.
#[test]
fn manifest_byte_identity_is_verified_before_json_parsing() {
    let value = linux_value();
    let (provider, _, io) = provider(&value, RuntimeInstallationState::Available);
    let identity = RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity");
    for bytes in [Vec::new(), vec![b'x'; (1 << 20) + 1], b"{}\n".to_vec()] {
        *io.bytes.lock().expect("bytes") = bytes;
        assert_eq!(
            provider.manifest(&identity).expect_err("identity failure"),
            RuntimeError::ExecutionManifestInvalid
        );
    }
}

// Rejects every source identity and platform mismatch after exact-byte verification.
#[test]
fn schema_and_persisted_identity_mutation_matrix_fails_closed() {
    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "schema",
            Box::new(|value| value["schema_version"] = json!(5)),
        ),
        (
            "candidate",
            Box::new(|value| value["id"] = json!("other--owner--model--target")),
        ),
        (
            "version",
            Box::new(|value| value["version"] = json!("2.0.0")),
        ),
        (
            "logical model",
            Box::new(|value| value["logical_model"] = json!("other-model")),
        ),
        (
            "target",
            Box::new(|value| value["target"]["id"] = json!("other-target")),
        ),
        (
            "platform",
            Box::new(|value| value["target"]["platform"] = json!("windows/x86_64")),
        ),
        (
            "protocol",
            Box::new(|value| value["engine"]["protocol"]["version"] = json!(1)),
        ),
        (
            "distribution",
            Box::new(|value| {
                value["engine"]["distribution"]["immutable_id"] =
                    json!(format!("sha256:{}", "f".repeat(64)))
            }),
        ),
        (
            "artifact",
            Box::new(|value| value["artifacts"][0]["revision"] = json!("f".repeat(40))),
        ),
        (
            "unknown root",
            Box::new(|value| value["unknown"] = json!(true)),
        ),
    ];
    for (name, mutate) in mutations {
        let mut value = linux_value();
        mutate(&mut value);
        let io = Arc::new(MockIo::new(manifest_bytes(&value)));
        // Preserve exact mutated file identity while retaining the original persisted semantics.
        let original = installation(&linux_value(), RuntimeInstallationState::Available);
        let runtime = RuntimeIdentity::new(
            original.runtime().candidate_id().clone(),
            original.runtime().version().clone(),
            original.runtime().target_id().clone(),
            original.runtime().source().clone(),
            original.runtime().engine_distribution().clone(),
            original.runtime().runtime_digest().clone(),
            digest(&manifest_bytes(&value)),
            original.runtime().execution_contract_digest().clone(),
        )
        .expect("runtime");
        let installations = Arc::new(MockInstallations::new(Some(
            RuntimeInstallation::new(
                original.installation_id().clone(),
                original.node_id().clone(),
                original.logical_model().clone(),
                runtime,
                original.artifacts().to_vec(),
                original.evidence_label(),
                RuntimeInstallationState::Available,
                None,
                original.timestamps(),
            )
            .expect("installation"),
        )));
        let provider = FilesystemRuntimeExecutionManifestProvider::new(
            INSTALLATION_ROOT.into(),
            CACHE_ROOT.into(),
            installations,
            io,
        )
        .expect("provider");
        assert_eq!(
            provider
                .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
                .unwrap_err(),
            RuntimeError::ExecutionManifestInvalid,
            "mutation={name}"
        );
    }
}

// Rejects malformed task identity, commands, environment, readiness, endpoint, and phases.
#[test]
fn orchestration_mutation_matrix_covers_every_external_task_boundary() {
    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "schema",
            Box::new(|value| value["orchestration"]["schema_version"] = json!(2)),
        ),
        (
            "policy",
            Box::new(|value| value["orchestration"]["failure_policy"] = json!("partial")),
        ),
        (
            "task id",
            Box::new(|value| value["orchestration"]["tasks"][1]["task_id"] = json!("task-4")),
        ),
        (
            "launcher",
            Box::new(|value| value["orchestration"]["tasks"][0]["launcher"] = json!("shell")),
        ),
        (
            "ports",
            Box::new(|value| value["orchestration"]["tasks"][0]["port_count"] = json!(0)),
        ),
        (
            "protected env",
            Box::new(|value| {
                value["orchestration"]["tasks"][0]["environment"] = json!({"LETSINFER_KEY": "x"})
            }),
        ),
        (
            "lowercase env",
            Box::new(|value| {
                value["orchestration"]["tasks"][0]["environment"] = json!({"task_mode": "x"})
            }),
        ),
        (
            "shell command",
            Box::new(|value| {
                value["orchestration"]["tasks"][1]["command"] = json!(["/bin/sh", "-c", "true"])
            }),
        ),
        (
            "readiness",
            Box::new(|value| value["orchestration"]["tasks"][1]["readiness"]["retries"] = json!(0)),
        ),
        (
            "endpoint",
            Box::new(|value| value["orchestration"]["endpoint_owner"] = json!("task-9")),
        ),
        (
            "duplicate phase",
            Box::new(|value| {
                value["orchestration"]["startup_order"] = json!([["task-0", "task-0"]])
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut value = parallel_value();
        mutate(&mut value);
        let (provider, _, _) = provider(&value, RuntimeInstallationState::Available);
        assert_eq!(
            provider
                .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
                .unwrap_err(),
            RuntimeError::ExecutionManifestInvalid,
            "mutation={name}"
        );
    }
}

// Rejects every native archive field that could change acquisition or host execution.
#[test]
fn native_distribution_mutation_matrix_fails_closed() {
    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "archive URL",
            Box::new(|value| {
                value["engine"]["distribution"]["archive"]["url"] =
                    json!("http://example.invalid/engine.tar.gz")
            }),
        ),
        (
            "archive digest",
            Box::new(|value| value["engine"]["distribution"]["archive"]["sha256"] = json!("wrong")),
        ),
        (
            "archive bytes",
            Box::new(|value| value["engine"]["distribution"]["archive"]["bytes"] = json!(0)),
        ),
        (
            "archive format",
            Box::new(|value| value["engine"]["distribution"]["archive"]["format"] = json!("tar")),
        ),
        (
            "archive prefix",
            Box::new(|value| {
                value["engine"]["distribution"]["archive"]["strip_prefix"] = json!("../engine")
            }),
        ),
        (
            "entrypoint",
            Box::new(|value| value["engine"]["distribution"]["entrypoint"] = json!("../adapter")),
        ),
        (
            "upstream executable",
            Box::new(|value| {
                value["engine"]["distribution"]["upstream_executable"] = json!("../engine")
            }),
        ),
        (
            "port count",
            Box::new(|value| value["engine"]["distribution"]["port_count"] = json!(1)),
        ),
    ];
    for (name, mutate) in mutations {
        let mut value = macos_value();
        mutate(&mut value);
        let (provider, _, _) = provider(&value, RuntimeInstallationState::Available);
        assert_eq!(
            provider
                .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
                .unwrap_err(),
            RuntimeError::ExecutionManifestInvalid,
            "mutation={name}"
        );
    }
}

// Rejects container, cache, serving, and execution-digest corruption independently.
#[test]
fn execution_policy_mutation_matrix_fails_closed() {
    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "memory",
            Box::new(|value| value["container"]["memory_bytes"] = json!(0)),
        ),
        (
            "shared memory",
            Box::new(|value| value["container"]["shm_bytes"] = json!(0)),
        ),
        (
            "cpuset",
            Box::new(|value| value["container"]["cpuset_cpus"] = json!("0-7;touch")),
        ),
        (
            "cache provider",
            Box::new(|value| value["cache"]["provider"] = json!("other")),
        ),
        (
            "cache replay",
            Box::new(|value| value["cache"]["replay_output_policy"] = Value::Null),
        ),
        (
            "connections",
            Box::new(|value| value["serving"]["max_connections"] = json!(0)),
        ),
        (
            "active requests",
            Box::new(|value| value["serving"]["max_active_requests"] = json!(129)),
        ),
        (
            "context",
            Box::new(|value| value["serving"]["max_context_tokens"] = json!(0)),
        ),
    ];
    for (name, mutate) in mutations {
        let mut value = linux_value();
        mutate(&mut value);
        let (provider, _, _) = provider(&value, RuntimeInstallationState::Available);
        assert_eq!(
            provider
                .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
                .unwrap_err(),
            RuntimeError::ExecutionManifestInvalid,
            "mutation={name}"
        );
    }
    let value = linux_value();
    let bad_execution = {
        let original = installation(&value, RuntimeInstallationState::Available);
        let runtime = RuntimeIdentity::new(
            original.runtime().candidate_id().clone(),
            original.runtime().version().clone(),
            original.runtime().target_id().clone(),
            original.runtime().source().clone(),
            original.runtime().engine_distribution().clone(),
            original.runtime().runtime_digest().clone(),
            original.runtime().manifest_digest().clone(),
            Sha256Digest::parse(&"f".repeat(64)).expect("wrong execution"),
        )
        .expect("runtime");
        RuntimeInstallation::new(
            original.installation_id().clone(),
            original.node_id().clone(),
            original.logical_model().clone(),
            runtime,
            original.artifacts().to_vec(),
            original.evidence_label(),
            RuntimeInstallationState::Available,
            None,
            original.timestamps(),
        )
        .expect("installation")
    };
    let installations = Arc::new(MockInstallations::new(Some(bad_execution)));
    let io = Arc::new(MockIo::new(manifest_bytes(&value)));
    let provider = FilesystemRuntimeExecutionManifestProvider::new(
        INSTALLATION_ROOT.into(),
        CACHE_ROOT.into(),
        installations,
        io,
    )
    .expect("provider");
    assert_eq!(
        provider
            .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
            .unwrap_err(),
        RuntimeError::ExecutionManifestInvalid
    );
}

// Adapts the complete versioned store without exposing revisions to execution consumers.
#[test]
fn stored_installation_provider_projects_only_the_snapshot() {
    struct MockStore(RuntimeInstallation);
    impl RuntimeInstallationStore for MockStore {
        // Returns the fixture as one versioned read.
        fn read(
            &self,
            installation_id: &RuntimeInstallationId,
        ) -> Result<Option<VersionedRuntimeInstallation>, RuntimeError> {
            Ok((self.0.installation_id() == installation_id)
                .then(|| VersionedRuntimeInstallation::new(self.0.clone(), 41)))
        }

        // Rejects unused broad reads in this narrow adapter test.
        fn all(&self) -> Result<Vec<VersionedRuntimeInstallation>, RuntimeError> {
            Err(RuntimeError::StoreUnavailable)
        }

        // Rejects unused creates in this narrow adapter test.
        fn create(
            &self,
            _installation: RuntimeInstallation,
        ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
            Err(RuntimeError::StoreUnavailable)
        }

        // Rejects unused replacements in this narrow adapter test.
        fn replace(
            &self,
            _installation: RuntimeInstallation,
            _expected_revision: u64,
        ) -> Result<VersionedRuntimeInstallation, RuntimeError> {
            Err(RuntimeError::StoreUnavailable)
        }

        // Rejects unused deletes in this narrow adapter test.
        fn delete(
            &self,
            _installation_id: &RuntimeInstallationId,
            _expected_revision: u64,
        ) -> Result<(), RuntimeError> {
            Err(RuntimeError::StoreUnavailable)
        }
    }
    let expected = installation(&linux_value(), RuntimeInstallationState::Available);
    let identity = expected.installation_id().clone();
    let provider = StoredRuntimeInstallationProvider::new(Arc::new(MockStore(expected.clone())));
    assert_eq!(
        provider.installation(&identity).expect("read"),
        Some(expected)
    );
}

// Rejects non-absolute or overlapping managed roots at the composition boundary.
#[test]
fn provider_constructor_rejects_invalid_managed_roots() {
    let installations = Arc::new(MockInstallations::new(None));
    let io = Arc::new(MockIo::new(Vec::new()));
    assert!(FilesystemRuntimeExecutionManifestProvider::new(
        "relative".into(),
        CACHE_ROOT.into(),
        installations.clone(),
        io.clone(),
    )
    .is_err());
    assert!(FilesystemRuntimeExecutionManifestProvider::new(
        INSTALLATION_ROOT.into(),
        INSTALLATION_ROOT.into(),
        installations,
        io,
    )
    .is_err());
}

// Rejects invalid typed mock values before a consumer can mistake them for verified output.
#[test]
fn typed_execution_constructors_reject_unsafe_mock_inputs() {
    assert!(RuntimeExecutionTask::new(
        TaskId::parse("task-0").expect("task"),
        RuntimeTaskLauncher::Manifest,
        vec![("LETSINFER_OVERRIDE".to_string(), "value".to_string())],
        1,
        1,
        true,
        RuntimeExecutionReadiness::Manifest,
    )
    .is_err());
    assert!(RuntimeExecutionContainer::new(0, 1, Duration::from_secs(1), None).is_err());
    assert!(RuntimeExecutionServing::new(1, 2, 1, "/token-count".to_string()).is_err());

    let value = linux_value();
    let (provider, _, _) = provider(&value, RuntimeInstallationState::Available);
    let valid = provider
        .manifest(&RuntimeInstallationId::parse(&"d".repeat(32)).expect("identity"))
        .expect("manifest");
    assert!(RuntimeExecutionManifest::new(
        valid.installation_id().clone(),
        valid.logical_model().clone(),
        RuntimeExecutionPlatform::MacosArm64,
        valid.engine_id().clone(),
        RuntimeExecutionDistribution::NativeArchive {
            entrypoint: PathBuf::from("../adapter"),
            upstream_executable: PathBuf::from("engine"),
            port_count: 2,
        },
        valid.engine_arguments().to_vec(),
        valid.engine_environment().to_vec(),
        valid.cache_provider().to_string(),
        valid.has_persistent_cache(),
        valid.container().clone(),
        valid.serving().clone(),
        valid.runtime_root().to_path_buf(),
        valid.model_root().to_path_buf(),
        valid.engine_root().to_path_buf(),
        valid.cache_root().to_path_buf(),
        valid.tasks().to_vec(),
        valid.startup_order().to_vec(),
    )
    .is_err());
}

// Exercises real bounded no-follow file reads without involving a runtime manager result mock.
#[test]
fn system_manifest_io_reads_regular_files_and_rejects_symlinks() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("runtime.json");
    fs::write(&path, b"{}\n").expect("write");
    let io = SystemRuntimeExecutionManifestIo;
    assert_eq!(io.read(&path, 16).expect("read"), b"{}\n");
    assert_eq!(
        io.read(&path, 2).expect_err("bound"),
        RuntimeError::ExecutionManifestUnavailable
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&path, directory.path().join("link.json")).expect("symlink");
        assert_eq!(
            io.read(&directory.path().join("link.json"), 16)
                .expect_err("no-follow"),
            RuntimeError::ExecutionManifestUnavailable
        );
    }
}
