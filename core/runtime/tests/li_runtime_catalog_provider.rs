// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use base64::Engine as _;
use li_core_interface::{
    Accelerator, AcceleratorMemory, AcceleratorVendor, ArtifactName, ArtifactRevision, ArtifactUri,
    BootId, ByteCount, ComputeCapability, CpuArchitecture, DisplayName, EngineDistribution,
    EvidenceLabel, HardwareObservation, HardwareObservationId, LogicalModelName, MemoryTopology,
    ModelArtifact, ModelArtifactFormat, NodeId, OperatingSystem, PlatformIdentity,
    ProcessorObservation, RuntimeCandidateId, RuntimeIdentity, RuntimeSource, RuntimeVersion,
    Sha256Digest, TechnicalName, UnixMilliseconds,
};
use li_runtime_manager::{
    Ed25519RuntimeCatalogSignatureVerifier, FilesystemRuntimeCatalogCache,
    FilesystemRuntimeCatalogHydrationWorkspace, OciRuntimeCatalogCandidateHydrator,
    RuntimeCandidate, RuntimeCatalogCache, RuntimeCatalogCacheEntry,
    RuntimeCatalogCandidateHydrator, RuntimeCatalogClock, RuntimeCatalogEngineDistribution,
    RuntimeCatalogHydrationWorkspace, RuntimeCatalogLoadOptions, RuntimeCatalogPackProvider,
    RuntimeCatalogRevocationAnchor, RuntimeCatalogSignatureKind, RuntimeCatalogSignatureVerifier,
    RuntimeCatalogTrustProvider, RuntimeCatalogTrustRoot, RuntimeError, RuntimeHttpClient,
    RuntimeHttpDownload, RuntimeHttpRequest, RuntimeHttpResponse, RuntimeManager,
    RuntimePackDocuments, RuntimeTarget, SignedRuntimeCatalogProvider,
    StaticRuntimeCatalogTrustProvider,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CATALOG_URL: &str = "https://catalog.example/catalog.json";
const ENGINE_SOURCE: &str = "ghcr.io/letsinferlabs/engine-images@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

// Returns one deterministic Linux NVIDIA hardware observation for target matching.
fn hardware() -> HardwareObservation {
    hardware_with_accelerators(vec![Accelerator::new(
        li_core_interface::DeviceId::parse("GPU-catalog").expect("device"),
        AcceleratorVendor::Nvidia,
        DisplayName::parse("NVIDIA GB10").expect("GPU"),
        AcceleratorMemory::new(MemoryTopology::Unified, None, None).expect("memory"),
        ComputeCapability::Cuda {
            architecture: TechnicalName::parse("sm_121").expect("architecture"),
            maximum_version: Some(TechnicalName::parse("cuda_13.0").expect("CUDA")),
        },
    )])
}

// Returns one hardware observation containing exactly the supplied accelerators.
fn hardware_with_accelerators(accelerators: Vec<Accelerator>) -> HardwareObservation {
    HardwareObservation::new(
        HardwareObservationId::parse(&"1".repeat(32)).expect("observation"),
        NodeId::parse(&"2".repeat(32)).expect("node"),
        BootId::parse("boot-catalog").expect("boot"),
        PlatformIdentity::new(OperatingSystem::Linux, CpuArchitecture::Arm64),
        ProcessorObservation::new(DisplayName::parse("Grace CPU").expect("CPU"), 20)
            .expect("processor"),
        ByteCount::new(128 << 30).expect("host memory"),
        accelerators,
        Vec::new(),
        UnixMilliseconds::new(1_000),
    )
    .expect("hardware")
}

// Returns one complete target contract with a configurable identity.
fn target(target_id: &str) -> Value {
    json!({
        "id": target_id,
        "platform": "linux/arm64",
        "accelerator": {
            "vendor": "nvidia",
            "architecture": "sm_121",
            "count": 1,
            "partitioning": "full-device"
        },
        "memory": {
            "topology": "unified",
            "minimum_total_gib": 64
        },
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
    })
}

// Returns one Apple Silicon target used to exercise native Engine catalog projections.
fn macos_target() -> Value {
    json!({
        "id": "macos-apple-silicon",
        "platform": "macos/arm64",
        "accelerator": {
            "vendor": "apple",
            "architecture": "apple-silicon",
            "count": 1,
            "partitioning": "full-device",
            "minimum_memory_gib": 64
        },
        "memory": {
            "topology": "unified",
            "minimum_total_gib": 64
        },
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
    })
}

// Returns one structured qualification waiver for a deterministic pull request.
fn waiver() -> Value {
    json!({
        "schema_version": 1,
        "policy": "allowlisted-maintainer-bypass-v1",
        "actor": {
            "github_login": "TaimurAyaz",
            "github_id": 7_026_217,
            "github_type": "User"
        },
        "reason": "Deterministic catalog fixture.",
        "comment_id": 9001,
        "comment_url": "https://github.com/letsinferlabs/runtimes/pull/42#issuecomment-9001",
        "issued_at": "2026-08-29T12:00:00Z"
    })
}

// Returns one complete signed-catalog release projection.
fn release(digest: char, consensus: char, score: f64) -> Value {
    let source_digest = digest.to_string().repeat(64);
    let consensus_digest = consensus.to_string().repeat(64);
    json!({
        "authors": [
            {
                "github_login": "RadixArk",
                "github_id": 10,
                "github_type": "User"
            },
            {
                "github_login": "letsinferlabs",
                "github_id": 20,
                "github_type": "Organization"
            }
        ],
        "license": "AGPL-3.0-only",
        "source": format!("ghcr.io/letsinferlabs/runtime-artifacts@sha256:{source_digest}"),
        "engine": "sglang",
        "engine_distribution": {
            "kind": "oci-container",
            "reference": ENGINE_SOURCE
        },
        "model_uri": "hf://RadixArk/Qwen3.8",
        "benchmark": {
            "id": "9".repeat(64),
            "suite": "letsinfer-code-prose-v1",
            "score": score
        },
        "provenance": {
            "repository": "letsinferlabs/runtimes",
            "pull_request": 42,
            "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/42",
            "proposal_head_sha": "1".repeat(40),
            "execution_sha256": "2".repeat(64),
            "qualified_commit_sha": "3".repeat(40),
            "consensus_sha256": consensus_digest
        },
        "verification": {
            "method": "allowlisted-maintainer-bypass-v1",
            "consensus_path": "sglang--radixark--qwen3.8--dgx-spark/benchmark.consensus.json",
            "consensus_sha256": consensus_digest,
            "verifiers": [],
            "waiver": waiver(),
            "benchmark_source": "author-benchmark-v1"
        }
    })
}

// Returns one stable-contract qualification carry matching current production recommendations.
fn migration_release() -> Value {
    let mut value = release('a', 'c', 1.0);
    value["verification"] = json!({
        "method": "runtime-contract-migration-v1",
        "from_version": "0.9.0",
        "from_source": format!(
            "ghcr.io/letsinferlabs/runtime-artifacts@sha256:{}",
            "7".repeat(64)
        ),
        "benchmark_record_path": "sglang--radixark--qwen3.8--dgx-spark/benchmark.previous.json",
        "benchmark_record_sha256": "8".repeat(64),
        "execution_contract_sha256": "6".repeat(64),
        "consensus_sha256": "c".repeat(64),
        "verifiers": []
    });
    value["provenance"] = json!({
        "method": "runtime-contract-migration-v1",
        "repository": "letsinferlabs/runtimes",
        "pull_request": 42,
        "pull_request_url": "https://github.com/letsinferlabs/runtimes/pull/42",
        "proposal_head_sha": "1".repeat(40),
        "qualified_commit_sha": "3".repeat(40),
        "from_version": "0.9.0",
        "from_source": format!(
            "ghcr.io/letsinferlabs/runtime-artifacts@sha256:{}",
            "7".repeat(64)
        ),
        "benchmark_record_sha256": "8".repeat(64),
        "execution_contract_sha256": "6".repeat(64),
        "consensus_sha256": "c".repeat(64)
    });
    value
}

// Returns one complete schema-7 catalog with two versions of one candidate.
fn catalog() -> Value {
    let candidate = "sglang--radixark--qwen3.8--dgx-spark";
    json!({
        "schema_version": 7,
        "recommendation_policy": {
            "id": "letsinfer-throughput-geomean-v1",
            "benchmark_suite": "letsinfer-code-prose-v1",
            "metric": "aggregate_tps",
            "cache": "uncached",
            "tie_breakers": ["score", "version", "candidate"]
        },
        "targets": {
            "dgx-spark": {"match": target("dgx-spark")}
        },
        "models": {
            "qwen3.8": {
                "targets": {
                    "dgx-spark": {
                        "recommended": {"candidate": candidate, "version": "2.0.0"},
                        "candidates": {
                            (candidate): {
                                "latest": "2.0.0",
                                "releases": {
                                    "1.0.0": migration_release(),
                                    "2.0.0": release('b', 'd', 2.0)
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

// Returns one complete schema-6 runtime that preserves the signed catalog projection.
fn hydrated_runtime() -> Value {
    json!({
        "schema_version": 6,
        "id": "sglang--radixark--qwen3.8--dgx-spark",
        "version": "2.0.0",
        "logical_model": "qwen3.8",
        "target": target("dgx-spark"),
        "engine": {
            "id": "sglang",
            "protocol": {"version": 2},
            "distribution": {
                "kind": "oci-container",
                "reference": ENGINE_SOURCE,
                "immutable_id": format!("sha256:{}", "e".repeat(64))
            },
            "model_format": "huggingface-snapshot",
            "cache_provider": "fixture-prefix-v1",
            "arguments": ["--context-length", "32768"],
            "environment": {"FIXTURE_MODE": "deterministic"}
        },
        "model": {
            "uri": "hf://RadixArk/Qwen3.8",
            "artifact": "model",
            "acquisition": {"kind": "huggingface-snapshot"}
        },
        "artifacts": [{
            "name": "model",
            "uri": "hf://RadixArk/Qwen3.8",
            "format": "huggingface-snapshot",
            "revision": "7".repeat(40)
        }],
        "container": {
            "memory_bytes": 68_719_476_736_u64,
            "shm_bytes": 8_589_934_592_u64,
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
            "max_context_tokens": 32_768,
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
            "cases": [{"id": "32k", "prompt_tokens": 32768, "concurrencies": [1]}]
        }}
    })
}

// Wraps exact runtime bytes in one deterministic verified-pack capability result.
fn hydrated_documents(runtime: Vec<u8>) -> RuntimePackDocuments {
    RuntimePackDocuments::from_verified(
        Sha256Digest::parse(&"d".repeat(64)).expect("descriptor digest"),
        b"verified descriptor fixture\n".to_vec(),
        runtime,
    )
}

// Returns one empty canonical revocation ledger.
fn empty_revocations() -> Value {
    json!({
        "schema_version": 1,
        "sequence": 0,
        "generated_at_unix": 0,
        "revocations": []
    })
}

// Returns compact deterministic JSON bytes with one trailing newline.
fn json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("JSON");
    bytes.push(b'\n');
    bytes
}

// Serves the four exact signed-document assets or one configured availability failure.
struct MockHttp {
    catalog: Mutex<Vec<u8>>,
    revocations: Mutex<Vec<u8>>,
    unavailable: AtomicBool,
    requests: AtomicUsize,
}

impl MockHttp {
    // Creates one deterministic asset server from catalog and ledger values.
    fn new(catalog: Vec<u8>, revocations: Vec<u8>) -> Self {
        Self {
            catalog: Mutex::new(catalog),
            revocations: Mutex::new(revocations),
            unavailable: AtomicBool::new(false),
            requests: AtomicUsize::new(0),
        }
    }
}

impl RuntimeHttpClient for MockHttp {
    // Returns one exact asset body while recording request count.
    fn get(
        &self,
        request: &RuntimeHttpRequest,
        _maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpResponse, RuntimeError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(RuntimeError::DownloadUnavailable);
        }
        let body = if request.url().ends_with("catalog.json") {
            self.catalog.lock().expect("catalog").clone()
        } else if request.url().ends_with("catalog.json.sig") {
            b"catalog-signature".to_vec()
        } else if request.url().ends_with("revocations.json") {
            self.revocations.lock().expect("revocations").clone()
        } else if request.url().ends_with("revocations.json.sig") {
            b"revocations-signature".to_vec()
        } else {
            return Err(RuntimeError::DownloadInvalid);
        };
        RuntimeHttpResponse::new(200, request.url().to_string(), BTreeMap::new(), body, false)
    }

    // Rejects streamed downloads because catalog assets are bounded metadata.
    fn download(
        &self,
        _request: &RuntimeHttpRequest,
        _destination: &Path,
        _maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpDownload, RuntimeError> {
        Err(RuntimeError::DownloadUnavailable)
    }
}

// Verifies that the provider passed each expected detached signature envelope.
struct MockSignatures {
    invalid: AtomicBool,
}

impl RuntimeCatalogSignatureVerifier for MockSignatures {
    // Accepts only the deterministic signature corresponding to each document kind.
    fn verify(
        &self,
        kind: RuntimeCatalogSignatureKind,
        _document: &[u8],
        signature: &[u8],
        _trust: &RuntimeCatalogTrustRoot,
    ) -> Result<(), RuntimeError> {
        let expected = match kind {
            RuntimeCatalogSignatureKind::Catalog => b"catalog-signature".as_slice(),
            RuntimeCatalogSignatureKind::Revocations => b"revocations-signature".as_slice(),
        };
        if self.invalid.load(Ordering::SeqCst) || signature != expected {
            Err(RuntimeError::CatalogSignatureInvalid)
        } else {
            Ok(())
        }
    }
}

// Retains one in-memory exact cache entry across provider calls.
#[derive(Default)]
struct MockCache {
    entry: Mutex<Option<RuntimeCatalogCacheEntry>>,
    anchors: Mutex<BTreeMap<String, RuntimeCatalogRevocationAnchor>>,
}

impl RuntimeCatalogCache for MockCache {
    // Returns the retained immutable entry.
    fn read(&self) -> Result<Option<RuntimeCatalogCacheEntry>, RuntimeError> {
        Ok(self.entry.lock().expect("cache").clone())
    }

    // Replaces the retained entry only after provider verification.
    fn write(&self, entry: &RuntimeCatalogCacheEntry) -> Result<(), RuntimeError> {
        *self.entry.lock().expect("cache") = Some(entry.clone());
        Ok(())
    }

    // Returns the independent source-keyed test anchor when present.
    fn read_revocation_anchor(
        &self,
        source: &str,
    ) -> Result<Option<RuntimeCatalogRevocationAnchor>, RuntimeError> {
        Ok(self.anchors.lock().expect("anchors").get(source).cloned())
    }

    // Enforces monotonic sequence and same-sequence document identity in memory.
    fn write_revocation_anchor(
        &self,
        anchor: &RuntimeCatalogRevocationAnchor,
    ) -> Result<(), RuntimeError> {
        let mut anchors = self.anchors.lock().expect("anchors");
        if let Some(existing) = anchors.get(anchor.source()) {
            if anchor.sequence() < existing.sequence()
                || (anchor.sequence() == existing.sequence()
                    && anchor.revocations_sha256() != existing.revocations_sha256())
            {
                return Err(RuntimeError::CatalogInvalid);
            }
        }
        anchors.insert(anchor.source().to_string(), anchor.clone());
        Ok(())
    }
}

// Supplies one mutable deterministic Unix timestamp.
struct MockClock(AtomicU64);

impl RuntimeCatalogClock for MockClock {
    // Returns the configured fixture timestamp.
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

// Hydrates one exact fixture release and can inject signed-projection mismatches.
struct MockHydrator {
    wrong_source: AtomicBool,
    wrong_primary_model: AtomicBool,
}

impl RuntimeCatalogCandidateHydrator for MockHydrator {
    // Builds the complete runtime-pack identity omitted from schema 7.
    fn hydrate(
        &self,
        release: &li_runtime_manager::RuntimeCatalogListEntry,
    ) -> Result<RuntimeCandidate, RuntimeError> {
        let source = if self.wrong_source.load(Ordering::SeqCst) {
            RuntimeSource::parse(&format!(
                "ghcr.io/letsinferlabs/runtime-artifacts@sha256:{}",
                "f".repeat(64)
            ))
            .expect("wrong source")
        } else {
            release.source().clone()
        };
        let (engine_reference, payload_id) = match release.engine_distribution() {
            RuntimeCatalogEngineDistribution::Oci {
                reference,
                payload_id,
            } => (reference.clone(), payload_id.clone()),
            RuntimeCatalogEngineDistribution::Native { .. } => {
                return Err(RuntimeError::EngineAcquisitionInvalid)
            }
        };
        let engine_digest = engine_reference
            .as_str()
            .rsplit_once("@sha256:")
            .expect("Engine digest")
            .1
            .to_string();
        RuntimeCandidate::new(
            release.logical_model().clone(),
            RuntimeIdentity::new(
                release.candidate_id().clone(),
                RuntimeVersion::parse(release.version()).expect("version"),
                release.target().id().clone(),
                source,
                EngineDistribution::oci(
                    engine_reference,
                    Sha256Digest::parse(&engine_digest).expect("Engine identity"),
                    None,
                    payload_id,
                ),
                Sha256Digest::parse(&"8".repeat(64)).expect("runtime descriptor digest"),
                Sha256Digest::parse(&"4".repeat(64)).expect("manifest"),
                Sha256Digest::parse(&"5".repeat(64)).expect("execution"),
            )
            .expect("runtime"),
            if self.wrong_primary_model.load(Ordering::SeqCst) {
                vec![
                    ModelArtifact::new(
                        ArtifactName::parse("model").expect("artifact"),
                        ArtifactUri::parse("hf://Other/Model").expect("wrong model URI"),
                        ArtifactRevision::parse(&"7".repeat(40)).expect("wrong revision"),
                        ModelArtifactFormat::HuggingFaceSnapshot,
                    ),
                    ModelArtifact::new(
                        ArtifactName::parse("tokenizer").expect("artifact"),
                        ArtifactUri::parse(release.model_uri()).expect("model URI"),
                        ArtifactRevision::parse(&"6".repeat(40)).expect("revision"),
                        ModelArtifactFormat::HuggingFaceSnapshot,
                    ),
                ]
            } else {
                vec![ModelArtifact::new(
                    ArtifactName::parse("model").expect("artifact"),
                    ArtifactUri::parse(release.model_uri()).expect("model URI"),
                    ArtifactRevision::parse(&"6".repeat(40)).expect("revision"),
                    ModelArtifactFormat::HuggingFaceSnapshot,
                )]
            },
            RuntimeTarget::new(
                OperatingSystem::Linux,
                CpuArchitecture::Arm64,
                li_runtime_manager::RuntimeAcceleratorVendor::Nvidia,
                TechnicalName::parse("sm_121").expect("architecture"),
                1,
                MemoryTopology::Unified,
                None,
                ByteCount::new(64 << 30).expect("memory"),
            )
            .expect("target"),
            EvidenceLabel::Qualified,
            2,
            release.is_recommended(),
            false,
        )
    }
}

struct Fixture {
    provider: Arc<SignedRuntimeCatalogProvider>,
    http: Arc<MockHttp>,
    signatures: Arc<MockSignatures>,
    cache: Arc<MockCache>,
    clock: Arc<MockClock>,
    hydrator: Arc<MockHydrator>,
}

// Supplies one verified runtime-pack document set behind an independently failing capability.
struct MockCatalogPack {
    documents: Mutex<RuntimePackDocuments>,
    document_failure: AtomicBool,
    cleanup_failure: AtomicBool,
    acquisitions: AtomicUsize,
    cleanups: AtomicUsize,
}

impl MockCatalogPack {
    // Creates one deterministic verified-pack provider.
    fn new(documents: RuntimePackDocuments) -> Self {
        Self {
            documents: Mutex::new(documents),
            document_failure: AtomicBool::new(false),
            cleanup_failure: AtomicBool::new(false),
            acquisitions: AtomicUsize::new(0),
            cleanups: AtomicUsize::new(0),
        }
    }
}

impl RuntimeCatalogPackProvider for MockCatalogPack {
    // Returns exact fixture documents after enforcing source and empty-workspace contracts.
    fn documents(
        &self,
        source: &RuntimeSource,
        workspace: &Path,
    ) -> Result<RuntimePackDocuments, RuntimeError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        assert!(source
            .as_str()
            .starts_with("ghcr.io/letsinferlabs/runtime-artifacts@sha256:"));
        assert!(workspace.read_dir().expect("workspace").next().is_none());
        if self.document_failure.load(Ordering::SeqCst) {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        Ok(self.documents.lock().expect("documents").clone())
    }

    // Records exact cleanup and can inject one post-hydration failure.
    fn clear(&self, workspace: &Path) -> Result<(), RuntimeError> {
        self.cleanups.fetch_add(1, Ordering::SeqCst);
        assert!(workspace.is_dir());
        if self.cleanup_failure.load(Ordering::SeqCst) {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(())
    }
}

// Retains all ephemeral state required by the production candidate hydrator.
struct HydrationFixture {
    _temporary: TempDir,
    provider: Arc<SignedRuntimeCatalogProvider>,
    packs: Arc<MockCatalogPack>,
}

// Creates one explicit owner-only root beneath a test temporary directory.
fn private_hydration_root(temporary: &TempDir) -> PathBuf {
    let root = temporary.path().join("hydration");
    fs::create_dir(&root).expect("hydration root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    }
    root
}

// Creates one signed provider composed with the production parser and workspace implementation.
fn hydration_fixture(documents: RuntimePackDocuments) -> HydrationFixture {
    let temporary = TempDir::new().expect("temporary");
    let packs = Arc::new(MockCatalogPack::new(documents));
    let workspaces = Arc::new(
        FilesystemRuntimeCatalogHydrationWorkspace::new(private_hydration_root(&temporary))
            .expect("workspaces"),
    );
    let hydrator = Arc::new(OciRuntimeCatalogCandidateHydrator::new(
        packs.clone(),
        workspaces,
    ));
    let provider = Arc::new(
        SignedRuntimeCatalogProvider::new(
            CATALOG_URL.to_string(),
            60,
            Arc::new(MockHttp::new(
                json_bytes(&catalog()),
                json_bytes(&empty_revocations()),
            )),
            Arc::new(MockSignatures {
                invalid: AtomicBool::new(false),
            }),
            Arc::new(StaticRuntimeCatalogTrustProvider::letsinfer().expect("trust")),
            Arc::new(MockCache::default()),
            hydrator,
            Arc::new(MockClock(AtomicU64::new(10_000))),
        )
        .expect("provider"),
    );
    HydrationFixture {
        _temporary: temporary,
        provider,
        packs,
    }
}

// Creates one complete provider fixture with every external capability retained.
fn fixture(catalog: Vec<u8>, revocations: Vec<u8>) -> Fixture {
    let http = Arc::new(MockHttp::new(catalog, revocations));
    let signatures = Arc::new(MockSignatures {
        invalid: AtomicBool::new(false),
    });
    let cache = Arc::new(MockCache::default());
    let clock = Arc::new(MockClock(AtomicU64::new(10_000)));
    let hydrator = Arc::new(MockHydrator {
        wrong_source: AtomicBool::new(false),
        wrong_primary_model: AtomicBool::new(false),
    });
    let trust: Arc<dyn RuntimeCatalogTrustProvider> =
        Arc::new(StaticRuntimeCatalogTrustProvider::letsinfer().expect("trust"));
    let provider = Arc::new(
        SignedRuntimeCatalogProvider::new(
            CATALOG_URL.to_string(),
            60,
            http.clone(),
            signatures.clone(),
            trust,
            cache.clone(),
            hydrator.clone(),
            clock.clone(),
        )
        .expect("provider"),
    );
    Fixture {
        provider,
        http,
        signatures,
        cache,
        clock,
        hydrator,
    }
}

// Uses one verified source for ordered list identity and automatic install resolution.
#[test]
fn valid_catalog_preserves_authors_and_resolves_the_same_recommendation() {
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&empty_revocations()));
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    let entries = fixture
        .provider
        .list(Some(&model), Some(&hardware()), true, false)
        .expect("list");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].version(), "2.0.0");
    assert!(entries[0].is_recommended());
    assert_eq!(entries[0].authors()[0].github_login(), "RadixArk");
    assert_eq!(entries[0].authors()[1].github_login(), "letsinferlabs");
    assert_eq!(entries[0].license(), "AGPL-3.0-only");
    assert_eq!(
        entries[1].verification_method(),
        "runtime-contract-migration-v1"
    );
    let manager = RuntimeManager::new(fixture.provider.clone());
    let selected = manager
        .select(&model, None, &hardware())
        .expect("automatic selection");
    assert_eq!(selected.runtime().version().as_str(), "2.0.0");
    assert_eq!(selected.runtime().source(), entries[0].source());
}

// Requires a hardware observation for compatible-only listing and ignores unrelated devices.
#[test]
fn compatible_listing_counts_only_accelerators_that_satisfy_the_complete_target() {
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&empty_revocations()));
    assert!(fixture
        .provider
        .list(None, None, true, false)
        .expect("compatible list without hardware")
        .is_empty());
    assert_eq!(
        fixture
            .provider
            .list(None, None, true, true)
            .expect("explicit all-target list")
            .len(),
        2
    );
    let mut accelerators = hardware().accelerators().to_vec();
    accelerators.push(Accelerator::new(
        li_core_interface::DeviceId::parse("GPU-unrelated").expect("device"),
        AcceleratorVendor::Apple,
        DisplayName::parse("Apple GPU").expect("GPU"),
        AcceleratorMemory::new(MemoryTopology::Unified, None, None).expect("memory"),
        ComputeCapability::Metal {
            family: TechnicalName::parse("apple9").expect("family"),
            version: TechnicalName::parse("metal4").expect("Metal"),
        },
    ));
    assert_eq!(
        fixture
            .provider
            .list(
                None,
                Some(&hardware_with_accelerators(accelerators)),
                true,
                false,
            )
            .expect("mixed hardware list")
            .len(),
        2
    );
}

// Preserves filters and snapshot identity while applying an explicit strict refresh policy.
#[test]
fn option_aware_listing_returns_one_verified_snapshot_and_never_stale_refresh() {
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&empty_revocations()));
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    let listing = fixture
        .provider
        .list_with_options(
            Some(&model),
            Some(&hardware()),
            true,
            false,
            RuntimeCatalogLoadOptions::refresh(false),
        )
        .expect("fresh listing");
    assert_eq!(listing.snapshot().source(), CATALOG_URL);
    assert!(!listing.snapshot().is_stale());
    assert_eq!(
        listing
            .entries()
            .iter()
            .map(|entry| (entry.version(), entry.target().id().as_str()))
            .collect::<Vec<_>>(),
        [("2.0.0", "dgx-spark"), ("1.0.0", "dgx-spark")]
    );

    fixture.http.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .list_with_options(
                Some(&model),
                Some(&hardware()),
                true,
                false,
                RuntimeCatalogLoadOptions::refresh(false),
            )
            .expect_err("strict refresh"),
        RuntimeError::CatalogUnavailable
    );
}

// Rejects representative schema, source, digest, target, duplicate-key, and corruption failures.
#[test]
fn catalog_validation_fails_closed_at_each_signed_identity_boundary() {
    let mut cases = Vec::new();
    let mut unsupported = catalog();
    unsupported["schema_version"] = json!(8);
    cases.push(json_bytes(&unsupported));
    let mut mutable_source = catalog();
    mutable_source["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"]
        ["sglang--radixark--qwen3.8--dgx-spark"]["releases"]["2.0.0"]["source"] =
        json!("ghcr.io/letsinferlabs/runtime-artifacts:latest");
    cases.push(json_bytes(&mutable_source));
    let mut mutable_engine = catalog();
    mutable_engine["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"]
        ["sglang--radixark--qwen3.8--dgx-spark"]["releases"]["2.0.0"]["engine_distribution"]
        ["reference"] = json!("ghcr.io/engine:latest");
    cases.push(json_bytes(&mutable_engine));
    let mut ambiguous_source = catalog();
    ambiguous_source["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"]
        ["sglang--radixark--qwen3.8--dgx-spark"]["releases"]["2.0.0"]["source"] = json!(format!(
        "ghcr.io/letsinferlabs/runtime-artifacts@latest@sha256:{}",
        "b".repeat(64)
    ));
    cases.push(json_bytes(&ambiguous_source));
    let mut target_mismatch = catalog();
    target_mismatch["targets"]["dgx-spark"]["match"]["id"] = json!("other-target");
    cases.push(json_bytes(&target_mismatch));
    cases.push(br#"{"schema_version":7,"schema_version":7}"#.to_vec());
    cases.push(b"{not-json".to_vec());
    for bytes in cases {
        let fixture = fixture(bytes, json_bytes(&empty_revocations()));
        assert_eq!(
            fixture
                .provider
                .load(RuntimeCatalogLoadOptions::refresh(false))
                .expect_err("invalid catalog"),
            RuntimeError::CatalogInvalid
        );
    }
}

// Accepts each schema-7 native Engine projection without adding Engine-specific policy.
#[test]
fn native_engine_projection_union_is_model_and_engine_agnostic() {
    for kind in [
        "native-archive",
        "python-standalone",
        "embedded-application",
    ] {
        let mut document = catalog();
        let old_candidate = "sglang--radixark--qwen3.8--dgx-spark";
        let new_candidate = "mlx-lm--radixark--qwen3.8--macos-apple-silicon";
        document["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"][old_candidate]
            ["releases"]["1.0.0"] = release('a', 'c', 1.0);
        let mut candidate = document["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"]
            [old_candidate]
            .take();
        for release in candidate["releases"]
            .as_object_mut()
            .expect("releases")
            .values_mut()
        {
            release["engine"] = json!("mlx-lm");
            release["engine_distribution"] = json!({
                "kind": kind,
                "platform": "macos/arm64",
                "payload_id": format!("sha256:{}", "e".repeat(64)),
                "source_revision": "f".repeat(40)
            });
            release["verification"]["consensus_path"] =
                json!(format!("{new_candidate}/benchmark.consensus.json"));
            if release["verification"]["method"] == "runtime-contract-migration-v1" {
                release["verification"]["benchmark_record_path"] =
                    json!(format!("{new_candidate}/benchmark.previous.json"));
            }
        }
        document["targets"] = json!({
            "macos-apple-silicon": {"match": macos_target()}
        });
        document["models"]["qwen3.8"]["targets"] = json!({
            "macos-apple-silicon": {
                "recommended": {"candidate": new_candidate, "version": "2.0.0"},
                "candidates": {(new_candidate): candidate}
            }
        });
        let fixture = fixture(json_bytes(&document), json_bytes(&empty_revocations()));
        let entries = fixture
            .provider
            .list(None, None, true, true)
            .expect("native catalog projection");
        assert_eq!(entries.len(), 2);
    }
}

// Applies the signed ledger before both list and automatic selection.
#[test]
fn revocation_removes_the_exact_release_and_recomputes_recommendation() {
    let ledger = json!({
        "schema_version": 1,
        "sequence": 1,
        "generated_at_unix": 9_999,
        "revocations": [{
            "runtime_oci_digest": format!("sha256:{}", "b".repeat(64)),
            "consensus_sha256": "d".repeat(64),
            "actor": {
                "github_login": "letsinferlabs",
                "github_id": 20,
                "github_type": "Organization"
            },
            "revoked_at_unix": 9_999,
            "reason_code": "output-correctness-failure",
            "verification_ids": ["8".repeat(64)],
            "replacement": null
        }]
    });
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&ledger));
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    let entries = fixture
        .provider
        .list(Some(&model), Some(&hardware()), true, false)
        .expect("active list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].version(), "1.0.0");
    assert!(entries[0].is_recommended());
    let selected = RuntimeManager::new(fixture.provider.clone())
        .select(&model, None, &hardware())
        .expect("active selection");
    assert_eq!(selected.runtime().version().as_str(), "1.0.0");
}

// Replays a fresh verified cache and permits stale use only for transport unavailability.
#[test]
fn cache_replay_and_stale_fallback_are_bounded_to_network_failure() {
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&empty_revocations()));
    fixture
        .provider
        .load(RuntimeCatalogLoadOptions::ordinary())
        .expect("fresh load");
    assert_eq!(fixture.http.requests.load(Ordering::SeqCst), 4);
    fixture
        .provider
        .load(RuntimeCatalogLoadOptions::ordinary())
        .expect("cache replay");
    assert_eq!(fixture.http.requests.load(Ordering::SeqCst), 4);
    fixture.clock.0.store(10_061, Ordering::SeqCst);
    fixture.http.unavailable.store(true, Ordering::SeqCst);
    let stale = fixture
        .provider
        .load(RuntimeCatalogLoadOptions::ordinary())
        .expect("verified stale fallback");
    assert!(stale.is_stale());
    assert_eq!(
        fixture
            .provider
            .load(RuntimeCatalogLoadOptions::refresh(false))
            .expect_err("stale disabled"),
        RuntimeError::CatalogUnavailable
    );
    fixture.http.unavailable.store(false, Ordering::SeqCst);
    fixture.signatures.invalid.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .load(RuntimeCatalogLoadOptions::refresh(true))
            .expect_err("invalid fresh signature cannot fall back"),
        RuntimeError::CatalogSignatureInvalid
    );
}

// Rejects a signed revocation ledger that rolls back or equivocates one cached sequence.
#[test]
fn refresh_enforces_monotonic_revocation_ledger_identity() {
    let mut ledger = empty_revocations();
    ledger["sequence"] = json!(2);
    ledger["generated_at_unix"] = json!(9_999);
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&ledger));
    fixture
        .provider
        .load(RuntimeCatalogLoadOptions::ordinary())
        .expect("initial ledger");

    let mut rollback = empty_revocations();
    rollback["sequence"] = json!(1);
    *fixture.http.revocations.lock().expect("revocations") = json_bytes(&rollback);
    assert_eq!(
        fixture
            .provider
            .load(RuntimeCatalogLoadOptions::refresh(false))
            .expect_err("ledger rollback"),
        RuntimeError::CatalogInvalid
    );

    let mut equivocation = empty_revocations();
    equivocation["sequence"] = json!(2);
    equivocation["generated_at_unix"] = json!(10_000);
    *fixture.http.revocations.lock().expect("revocations") = json_bytes(&equivocation);
    assert_eq!(
        fixture
            .provider
            .load(RuntimeCatalogLoadOptions::refresh(false))
            .expect_err("same-sequence replacement"),
        RuntimeError::CatalogInvalid
    );

    equivocation["sequence"] = json!(3);
    equivocation["generated_at_unix"] = json!(10_001);
    *fixture.http.revocations.lock().expect("revocations") = json_bytes(&equivocation);
    assert_eq!(
        fixture
            .provider
            .load(RuntimeCatalogLoadOptions::refresh(false))
            .expect("advanced ledger")
            .revocation_sequence(),
        3
    );
}

// Rejects a rolled-back cache pointer through the independent durable sequence anchor.
#[test]
fn revocation_anchor_survives_cache_pointer_rollback() {
    let mut ledger = empty_revocations();
    ledger["sequence"] = json!(2);
    ledger["generated_at_unix"] = json!(9_999);
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&ledger));
    fixture
        .provider
        .load(RuntimeCatalogLoadOptions::ordinary())
        .expect("initial ledger");
    let anchor = fixture
        .cache
        .read_revocation_anchor(CATALOG_URL)
        .expect("anchor")
        .expect("persisted anchor");
    assert_eq!(anchor.sequence(), 2);

    let rollback = RuntimeCatalogCacheEntry::new(
        CATALOG_URL.to_string(),
        json_bytes(&catalog()),
        b"catalog-signature".to_vec(),
        json_bytes(&empty_revocations()),
        b"revocations-signature".to_vec(),
        10_000,
    )
    .expect("rollback entry");
    *fixture.cache.entry.lock().expect("cache") = Some(rollback);
    fixture.http.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .provider
            .load(RuntimeCatalogLoadOptions::ordinary())
            .expect_err("rolled-back cache"),
        RuntimeError::CatalogUnavailable
    );
    assert_eq!(
        fixture
            .cache
            .read_revocation_anchor(CATALOG_URL)
            .expect("anchor")
            .expect("persisted anchor"),
        anchor
    );
}

// Rejects a hydrated runtime whose immutable source differs from the signed release.
#[test]
fn hydrated_candidate_must_preserve_every_catalog_identity() {
    let fixture = fixture(json_bytes(&catalog()), json_bytes(&empty_revocations()));
    fixture.hydrator.wrong_source.store(true, Ordering::SeqCst);
    assert_eq!(
        RuntimeManager::new(fixture.provider.clone())
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(),
            )
            .expect_err("source mismatch"),
        RuntimeError::CatalogInvalid
    );
    fixture.hydrator.wrong_source.store(false, Ordering::SeqCst);
    fixture
        .hydrator
        .wrong_primary_model
        .store(true, Ordering::SeqCst);
    assert_eq!(
        RuntimeManager::new(fixture.provider.clone())
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(),
            )
            .expect_err("secondary-only model match"),
        RuntimeError::CatalogInvalid
    );
}

// Hydrates a complete schema-6 runtime through verified pack and private workspace capabilities.
#[test]
fn production_catalog_hydrator_builds_one_exact_candidate_and_cleans_bytes() {
    let fixture = hydration_fixture(hydrated_documents(json_bytes(&hydrated_runtime())));
    let candidate = RuntimeManager::new(fixture.provider)
        .select(
            &LogicalModelName::parse("qwen3.8").expect("model"),
            None,
            &hardware(),
        )
        .expect("candidate");
    assert_eq!(candidate.runtime().version().as_str(), "2.0.0");
    assert_eq!(
        candidate.runtime().runtime_digest().as_str(),
        "d".repeat(64)
    );
    assert_eq!(candidate.artifacts().len(), 1);
    assert_eq!(candidate.artifacts()[0].revision().as_str(), "7".repeat(40));
    assert_eq!(fixture.packs.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.packs.cleanups.load(Ordering::SeqCst), 1);
    assert!(fixture
        ._temporary
        .path()
        .join("hydration")
        .read_dir()
        .expect("temporary")
        .next()
        .is_none());
}

// Rejects signed-projection changes, partial schema documents, and duplicate JSON fields.
#[test]
fn production_catalog_hydrator_rejects_every_material_identity_boundary() {
    let mut mutations = Vec::new();
    let mut wrong_candidate = hydrated_runtime();
    wrong_candidate["id"] = json!("sglang--other--model--dgx-spark");
    mutations.push(json_bytes(&wrong_candidate));
    let mut wrong_target = hydrated_runtime();
    wrong_target["target"]["accelerator"]["count"] = json!(2);
    mutations.push(json_bytes(&wrong_target));
    let mut wrong_engine = hydrated_runtime();
    wrong_engine["engine"]["distribution"]["reference"] = json!(format!(
        "ghcr.io/letsinferlabs/engine-images@sha256:{}",
        "f".repeat(64)
    ));
    mutations.push(json_bytes(&wrong_engine));
    let mut partial = hydrated_runtime();
    partial.as_object_mut().expect("runtime").remove("serving");
    mutations.push(json_bytes(&partial));
    let mut duplicate = serde_json::to_vec(&hydrated_runtime()).expect("runtime");
    assert_eq!(duplicate.pop(), Some(b'}'));
    duplicate.extend_from_slice(b",\"schema_version\":6}\n");
    mutations.push(duplicate);

    for runtime in mutations {
        let fixture = hydration_fixture(hydrated_documents(runtime));
        assert_eq!(
            RuntimeManager::new(fixture.provider)
                .select(
                    &LogicalModelName::parse("qwen3.8").expect("model"),
                    None,
                    &hardware(),
                )
                .expect_err("invalid hydration"),
            RuntimeError::CatalogInvalid
        );
        assert_eq!(fixture.packs.cleanups.load(Ordering::SeqCst), 1);
    }
}

// Preserves acquisition errors and treats failed byte cleanup as a failed hydration.
#[test]
fn production_catalog_hydrator_cleans_every_success_and_failure_path() {
    let unavailable = hydration_fixture(hydrated_documents(json_bytes(&hydrated_runtime())));
    unavailable
        .packs
        .document_failure
        .store(true, Ordering::SeqCst);
    assert_eq!(
        RuntimeManager::new(unavailable.provider)
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(),
            )
            .expect_err("unavailable pack"),
        RuntimeError::RuntimePackAcquisitionUnavailable
    );
    assert_eq!(unavailable.packs.cleanups.load(Ordering::SeqCst), 1);

    let cleanup = hydration_fixture(hydrated_documents(json_bytes(&hydrated_runtime())));
    cleanup.packs.cleanup_failure.store(true, Ordering::SeqCst);
    assert_eq!(
        RuntimeManager::new(cleanup.provider)
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(),
            )
            .expect_err("cleanup failure"),
        RuntimeError::CatalogCacheUnavailable
    );
}

// Creates unique owner-only workspaces and refuses foreign or non-empty deletion targets.
#[test]
fn filesystem_hydration_workspace_is_exact_private_and_non_recursive() {
    let temporary = TempDir::new().expect("temporary");
    let root = private_hydration_root(&temporary);
    let workspaces = FilesystemRuntimeCatalogHydrationWorkspace::new(root).expect("workspaces");
    let first = workspaces.create().expect("first");
    let second = workspaces.create().expect("second");
    assert_ne!(first, second);
    fs::write(first.join("retained"), b"bytes").expect("retained");
    assert_eq!(
        workspaces.remove(&first).expect_err("non-empty"),
        RuntimeError::CatalogCacheUnavailable
    );
    fs::remove_file(first.join("retained")).expect("remove retained");
    workspaces.remove(&first).expect("remove first");
    workspaces.remove(&second).expect("remove second");
    assert_eq!(
        workspaces
            .remove(temporary.path())
            .expect_err("foreign root"),
        RuntimeError::CatalogCacheUnavailable
    );
}

// Never falls back from absent qualification to an arbitrary unscored release.
#[test]
fn automatic_selection_requires_an_active_recommendation() {
    let mut document = catalog();
    document["models"]["qwen3.8"]["targets"]["dgx-spark"]["recommended"] = Value::Null;
    document["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"]
        ["sglang--radixark--qwen3.8--dgx-spark"]["releases"]["1.0.0"] = release('a', 'c', 1.0);
    for release in document["models"]["qwen3.8"]["targets"]["dgx-spark"]["candidates"]
        ["sglang--radixark--qwen3.8--dgx-spark"]["releases"]
        .as_object_mut()
        .expect("releases")
        .values_mut()
    {
        release["benchmark"] = Value::Null;
        release["verification"]
            .as_object_mut()
            .expect("verification")
            .remove("benchmark_source");
    }
    let fixture = fixture(json_bytes(&document), json_bytes(&empty_revocations()));
    let model = LogicalModelName::parse("qwen3.8").expect("model");
    assert_eq!(
        RuntimeManager::new(fixture.provider.clone())
            .select(&model, None, &hardware())
            .expect_err("automatic fallback"),
        RuntimeError::CandidateNotFound
    );
    let explicit =
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate");
    assert!(RuntimeManager::new(fixture.provider.clone())
        .select(&model, Some(&explicit), &hardware())
        .is_ok());
}

// Verifies production Ed25519 envelopes and rejects content and key-identity changes.
#[test]
fn production_signature_verifier_binds_document_kind_digest_and_trust_key() {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).expect("key pair");
    let public_key: [u8; 32] = pair.public_key().as_ref().try_into().expect("public key");
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&public_key);
    let key_id = Sha256Digest::parse(&hex_sha256(&der)).expect("key identity");
    let trust = RuntimeCatalogTrustRoot::new(public_key, key_id).expect("trust");
    let document = b"{\"schema_version\":7}\n";
    let signature = pair.sign(document);
    let envelope = json_bytes(&json!({
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id_sha256": trust.key_id().as_str(),
        "catalog_sha256": hex_sha256(document),
        "signature_base64": base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
    }));
    let verifier = Ed25519RuntimeCatalogSignatureVerifier;
    verifier
        .verify(
            RuntimeCatalogSignatureKind::Catalog,
            document,
            &envelope,
            &trust,
        )
        .expect("valid signature");
    let revocation_envelope = json_bytes(&json!({
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id_sha256": trust.key_id().as_str(),
        "document_kind": "letsinfer.revocations",
        "document_sha256": hex_sha256(document),
        "signature_base64": base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
    }));
    verifier
        .verify(
            RuntimeCatalogSignatureKind::Revocations,
            document,
            &revocation_envelope,
            &trust,
        )
        .expect("valid revocation signature");
    assert_eq!(
        verifier
            .verify(
                RuntimeCatalogSignatureKind::Catalog,
                b"{\"schema_version\":8}\n",
                &envelope,
                &trust,
            )
            .expect_err("changed bytes"),
        RuntimeError::CatalogSignatureInvalid
    );
}

// Persists exact immutable bytes and rejects a hard-linked cache object on restart.
#[test]
fn filesystem_cache_roundtrips_and_rejects_aliased_object_files() {
    let temporary = TempDir::new().expect("temporary");
    let root = temporary.path().join("catalog-cache");
    let cache = Arc::new(FilesystemRuntimeCatalogCache::new(root.clone()).expect("cache"));
    let entry = RuntimeCatalogCacheEntry::new(
        CATALOG_URL.to_string(),
        json_bytes(&catalog()),
        b"catalog-signature".to_vec(),
        json_bytes(&empty_revocations()),
        b"revocations-signature".to_vec(),
        10_000,
    )
    .expect("entry");
    cache.write(&entry).expect("write");
    assert_eq!(cache.read().expect("read"), Some(entry.clone()));
    let anchor = RuntimeCatalogRevocationAnchor::new(
        CATALOG_URL.to_string(),
        2,
        Sha256Digest::parse(&hex_sha256(entry.revocations())).expect("revocations digest"),
    )
    .expect("anchor");
    cache
        .write_revocation_anchor(&anchor)
        .expect("write anchor");
    assert_eq!(
        cache
            .read_revocation_anchor(CATALOG_URL)
            .expect("read anchor"),
        Some(anchor.clone())
    );
    assert_eq!(
        cache
            .write_revocation_anchor(
                &RuntimeCatalogRevocationAnchor::new(
                    CATALOG_URL.to_string(),
                    1,
                    anchor.revocations_sha256().clone(),
                )
                .expect("rollback anchor"),
            )
            .expect_err("anchor rollback"),
        RuntimeError::CatalogInvalid
    );
    assert_eq!(
        cache
            .write_revocation_anchor(
                &RuntimeCatalogRevocationAnchor::new(
                    CATALOG_URL.to_string(),
                    2,
                    Sha256Digest::parse(&"f".repeat(64)).expect("equivocation digest"),
                )
                .expect("equivocation anchor"),
            )
            .expect_err("anchor equivocation"),
        RuntimeError::CatalogInvalid
    );
    let barrier = Arc::new(Barrier::new(3));
    let handles = [(3, '3'), (4, '4')]
        .into_iter()
        .map(|(sequence, digest_character)| {
            let cache = cache.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let candidate = RuntimeCatalogRevocationAnchor::new(
                    CATALOG_URL.to_string(),
                    sequence,
                    Sha256Digest::parse(&digest_character.to_string().repeat(64))
                        .expect("candidate digest"),
                )
                .expect("candidate anchor");
                barrier.wait();
                cache.write_revocation_anchor(&candidate)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("anchor writer"))
        .collect::<Vec<_>>();
    assert!(results.iter().any(Result::is_ok));
    assert_eq!(
        cache
            .read_revocation_anchor(CATALOG_URL)
            .expect("concurrent anchor")
            .expect("anchor")
            .sequence(),
        4
    );
    let refreshed = RuntimeCatalogCacheEntry::new(
        CATALOG_URL.to_string(),
        entry.catalog().to_vec(),
        entry.catalog_signature().to_vec(),
        entry.revocations().to_vec(),
        entry.revocations_signature().to_vec(),
        20_000,
    )
    .expect("refreshed entry");
    cache
        .write(&refreshed)
        .expect("refresh unchanged immutable object");
    assert_eq!(cache.read().expect("refreshed read"), Some(refreshed));
    let catalog_path = root
        .join("objects")
        .join(entry.snapshot_sha256().as_str())
        .join("catalog.json");
    fs::hard_link(&catalog_path, temporary.path().join("catalog-alias")).expect("hard link");
    assert_eq!(
        cache.read().expect_err("hard-linked object"),
        RuntimeError::CatalogCacheUnavailable
    );
    assert_eq!(
        RuntimeCatalogCacheEntry::new(
            "https:///catalog.json".to_string(),
            entry.catalog().to_vec(),
            entry.catalog_signature().to_vec(),
            entry.revocations().to_vec(),
            entry.revocations_signature().to_vec(),
            30_000,
        )
        .expect_err("empty HTTPS authority"),
        RuntimeError::CatalogCacheUnavailable
    );
}

// Rejects automatic selection when two signed target contracts match the same host.
#[test]
fn automatic_selection_rejects_ambiguous_compatible_targets() {
    let mut document = catalog();
    document["targets"]["dgx-spark-copy"] = json!({"match": target("dgx-spark-copy")});
    let original = document["models"]["qwen3.8"]["targets"]["dgx-spark"].clone();
    let mut copied = original;
    let old_candidate = "sglang--radixark--qwen3.8--dgx-spark";
    let new_candidate = "sglang--radixark--qwen3.8--dgx-spark-copy";
    let mut candidate = copied["candidates"][old_candidate].take();
    for release in candidate["releases"]
        .as_object_mut()
        .expect("releases")
        .values_mut()
    {
        if release["verification"]["method"] == "runtime-contract-migration-v1" {
            release["verification"]["benchmark_record_path"] =
                json!(format!("{new_candidate}/benchmark.previous.json"));
        } else {
            release["verification"]["consensus_path"] =
                json!(format!("{new_candidate}/benchmark.consensus.json"));
        }
    }
    copied["candidates"] = json!({(new_candidate): candidate});
    copied["recommended"]["candidate"] = json!(new_candidate);
    document["models"]["qwen3.8"]["targets"]["dgx-spark-copy"] = copied;
    let fixture = fixture(json_bytes(&document), json_bytes(&empty_revocations()));
    assert_eq!(
        RuntimeManager::new(fixture.provider.clone())
            .select(
                &LogicalModelName::parse("qwen3.8").expect("model"),
                None,
                &hardware(),
            )
            .expect_err("ambiguous targets"),
        RuntimeError::CatalogTargetAmbiguous
    );
}

// Returns one lowercase SHA-256 string for a deterministic test identity.
fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
