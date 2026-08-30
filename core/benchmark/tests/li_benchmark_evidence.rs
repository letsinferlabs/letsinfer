// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use li_benchmark_manager::{
    canonical_benchmark_json_bytes, BenchmarkCommunityVerificationDocument,
    BenchmarkCommunityVerificationDocumentProvider, BenchmarkError, BenchmarkEvidenceEntryKind,
    BenchmarkEvidenceFileMetadata, BenchmarkEvidenceIoError, BenchmarkEvidenceNativeIo,
    BenchmarkEvidenceProvider, BenchmarkEvidencePublishDisposition, BenchmarkExecutionOutcome,
    BenchmarkFailure, BenchmarkFailureCategory, BenchmarkGitRevision, BenchmarkKind,
    BenchmarkRecordSchema, BenchmarkRequest, BenchmarkRestoration, BenchmarkScope,
    BenchmarkSignature, BenchmarkSigningCommand, BenchmarkSigningCommandOutput,
    BenchmarkSigningCommandRunner, BenchmarkSigningProvider, BenchmarkSubject,
    BenchmarkTelemetryReceipt, FilesystemBenchmarkEvidenceProvider,
    OpensslBenchmarkSigningProvider, RoutedBenchmarkEvidenceProvider,
};
use li_core_interface::{
    InstallationId, LogicalModelName, OperationId, PlacementGroupId, RuntimeCandidateId,
    RuntimeInstallationId, Sha256Digest,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const OWNER: u32 = 501;
const SOURCE_ROOT: &str = "/source";
const EVIDENCE_ROOT: &str = "/evidence";
const WORKSPACE_ROOT: &str = "/workspace";
const KEY_ROOT: &str = "/keys";
const OPENSSL: &str = "/usr/bin/openssl";
const PRIVATE_KEY: &str = "/keys/device-ed25519.key";
const PUBLIC_KEY: &str = "/keys/device-ed25519.pub";

// Stores one deterministic in-memory native filesystem entry.
#[derive(Clone)]
struct MockEntry {
    metadata: BenchmarkEvidenceFileMetadata,
    bytes: Vec<u8>,
}

// Implements the exact evidence I/O contract with deterministic failure injection.
#[derive(Default)]
struct MockIo {
    entries: Mutex<BTreeMap<PathBuf, MockEntry>>,
    failures: Mutex<BTreeMap<&'static str, usize>>,
    partial_read: Mutex<bool>,
    partial_write: Mutex<bool>,
    events: Mutex<Vec<String>>,
}

impl MockIo {
    // Inserts one owner-bound private directory fixture.
    fn directory(&self, path: impl Into<PathBuf>) {
        self.entries.lock().expect("entries").insert(
            path.into(),
            MockEntry {
                metadata: BenchmarkEvidenceFileMetadata::new(
                    BenchmarkEvidenceEntryKind::Directory,
                    OWNER,
                    0o700,
                    2,
                    0,
                ),
                bytes: Vec::new(),
            },
        );
    }

    // Inserts one explicit file fixture with caller-controlled safety metadata.
    fn file_with_metadata(
        &self,
        path: impl Into<PathBuf>,
        bytes: Vec<u8>,
        kind: BenchmarkEvidenceEntryKind,
        owner: u32,
        mode: u32,
        links: u64,
    ) {
        self.entries.lock().expect("entries").insert(
            path.into(),
            MockEntry {
                metadata: BenchmarkEvidenceFileMetadata::new(
                    kind,
                    owner,
                    mode,
                    links,
                    bytes.len() as u64,
                ),
                bytes,
            },
        );
    }

    // Inserts one ordinary owner-only, single-link file fixture.
    fn file(&self, path: impl Into<PathBuf>, bytes: Vec<u8>) {
        self.file_with_metadata(
            path,
            bytes,
            BenchmarkEvidenceEntryKind::RegularFile,
            OWNER,
            0o600,
            1,
        );
    }

    // Inserts one immutable root-owned executable fixture.
    fn executable(&self, path: impl Into<PathBuf>) {
        self.file_with_metadata(
            path,
            vec![0x7f, b'E', b'L', b'F'],
            BenchmarkEvidenceEntryKind::RegularFile,
            0,
            0o755,
            1,
        );
    }

    // Replaces one existing entry's metadata without changing its bytes.
    fn set_metadata(&self, path: &Path, metadata: BenchmarkEvidenceFileMetadata) {
        self.entries
            .lock()
            .expect("entries")
            .get_mut(path)
            .expect("entry")
            .metadata = metadata;
    }

    // Schedules one exact native operation to fail the requested number of times.
    fn fail(&self, operation: &'static str, count: usize) {
        self.failures
            .lock()
            .expect("failures")
            .insert(operation, count);
    }

    // Enables one truncated read result while retaining the original metadata size.
    fn partial_read(&self) {
        *self.partial_read.lock().expect("partial read") = true;
    }

    // Enables one partial temporary write followed by an I/O failure.
    fn partial_write(&self) {
        *self.partial_write.lock().expect("partial write") = true;
    }

    // Returns whether one path currently exists.
    fn contains(&self, path: &Path) -> bool {
        self.entries.lock().expect("entries").contains_key(path)
    }

    // Returns the complete bytes stored at one exact path.
    fn bytes(&self, path: &Path) -> Vec<u8> {
        self.entries
            .lock()
            .expect("entries")
            .get(path)
            .expect("entry")
            .bytes
            .clone()
    }

    // Returns how often one native operation was observed.
    fn event_count(&self, event: &str) -> usize {
        self.events
            .lock()
            .expect("events")
            .iter()
            .filter(|observed| observed.as_str() == event)
            .count()
    }

    // Consumes one scheduled operation failure.
    fn should_fail(&self, operation: &'static str) -> bool {
        let mut failures = self.failures.lock().expect("failures");
        let Some(remaining) = failures.get_mut(operation) else {
            return false;
        };
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        true
    }

    // Records one stable native operation name.
    fn record(&self, operation: &str) {
        self.events
            .lock()
            .expect("events")
            .push(operation.to_string());
    }
}

impl BenchmarkEvidenceNativeIo for MockIo {
    // Returns one deterministic no-follow metadata snapshot.
    fn metadata(
        &self,
        path: &Path,
    ) -> Result<Option<BenchmarkEvidenceFileMetadata>, BenchmarkEvidenceIoError> {
        self.record("metadata");
        if self.should_fail("metadata") {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        Ok(self
            .entries
            .lock()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?
            .get(path)
            .map(|entry| entry.metadata))
    }

    // Returns exact bytes or one deliberately truncated read.
    fn read_file(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, BenchmarkEvidenceIoError> {
        self.record("read");
        if self.should_fail("read") {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        let entries = self
            .entries
            .lock()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        let mut bytes = entries
            .get(path)
            .ok_or(BenchmarkEvidenceIoError::Unavailable)?
            .bytes
            .clone();
        if bytes.len() > maximum_bytes {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        let mut partial = self
            .partial_read
            .lock()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        if *partial && !bytes.is_empty() {
            *partial = false;
            bytes.pop();
        }
        Ok(bytes)
    }

    // Writes one complete fixture or leaves one partial file before failing.
    fn write_private_file(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), BenchmarkEvidenceIoError> {
        self.record("write");
        if self.should_fail("write") {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        let partial = {
            let mut partial = self
                .partial_write
                .lock()
                .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
            let current = *partial;
            *partial = false;
            current
        };
        let retained = if partial && !bytes.is_empty() {
            bytes[..bytes.len() - 1].to_vec()
        } else {
            bytes.to_vec()
        };
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        if entries.contains_key(path) {
            return Err(BenchmarkEvidenceIoError::AlreadyExists);
        }
        entries.insert(
            path.to_path_buf(),
            MockEntry {
                metadata: BenchmarkEvidenceFileMetadata::new(
                    BenchmarkEvidenceEntryKind::RegularFile,
                    OWNER,
                    0o600,
                    1,
                    retained.len() as u64,
                ),
                bytes: retained,
            },
        );
        if partial {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        Ok(())
    }

    // Atomically moves one complete temporary fixture unless the destination exists.
    fn publish_file(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<BenchmarkEvidencePublishDisposition, BenchmarkEvidenceIoError> {
        self.record("publish");
        if self.should_fail("publish") {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?;
        if entries.contains_key(destination) {
            return Ok(BenchmarkEvidencePublishDisposition::Existing);
        }
        let entry = entries
            .remove(temporary)
            .ok_or(BenchmarkEvidenceIoError::Unavailable)?;
        entries.insert(destination.to_path_buf(), entry);
        Ok(BenchmarkEvidencePublishDisposition::Published)
    }

    // Removes one exact provider-owned fixture.
    fn remove_private_file(&self, path: &Path) -> Result<(), BenchmarkEvidenceIoError> {
        self.record("remove");
        if self.should_fail("remove") {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        self.entries
            .lock()
            .map_err(|_| BenchmarkEvidenceIoError::Unavailable)?
            .remove(path);
        Ok(())
    }

    // Records one deterministic directory synchronization boundary.
    fn sync_directory(&self, _path: &Path) -> Result<(), BenchmarkEvidenceIoError> {
        self.record("sync");
        if self.should_fail("sync") {
            return Err(BenchmarkEvidenceIoError::Unavailable);
        }
        Ok(())
    }
}

// Queues deterministic OpenSSL output while retaining every exact command.
#[derive(Default)]
struct CommandMock {
    outputs: Mutex<VecDeque<Result<BenchmarkSigningCommandOutput, BenchmarkError>>>,
    commands: Mutex<Vec<BenchmarkSigningCommand>>,
}

impl CommandMock {
    // Queues one exact successful or failed native command result.
    fn push(&self, status: i32, stdout: &[u8]) {
        self.outputs
            .lock()
            .expect("outputs")
            .push_back(BenchmarkSigningCommandOutput::new(
                status,
                stdout.to_vec(),
                Vec::new(),
                false,
            ));
    }

    // Queues one runner-level failure before a process result exists.
    fn fail(&self) {
        self.outputs
            .lock()
            .expect("outputs")
            .push_back(Err(BenchmarkError::provider(
                "signing",
                "mock failure at /usr/bin/openssl using /keys/device-ed25519.key",
            )));
    }

    // Returns every command in invocation order.
    fn commands(&self) -> Vec<BenchmarkSigningCommand> {
        self.commands.lock().expect("commands").clone()
    }
}

impl BenchmarkSigningCommandRunner for CommandMock {
    // Returns the next exact mocked OpenSSL result.
    fn run(
        &self,
        command: &BenchmarkSigningCommand,
    ) -> Result<BenchmarkSigningCommandOutput, BenchmarkError> {
        self.commands
            .lock()
            .map_err(|_| BenchmarkError::provider("signing", "mock state failure"))?
            .push(command.clone());
        self.outputs
            .lock()
            .map_err(|_| BenchmarkError::provider("signing", "mock state failure"))?
            .pop_front()
            .ok_or_else(|| BenchmarkError::provider("signing", "missing mock output"))?
    }
}

// Carries one complete deterministic evidence test fixture.
struct EvidenceFixture {
    job_id: OperationId,
    request: BenchmarkRequest,
    outcome: BenchmarkExecutionOutcome,
    telemetry: BenchmarkTelemetryReceipt,
    restoration: BenchmarkRestoration,
    bytes: Vec<u8>,
    evidence_id: Sha256Digest,
    results_sha256: Sha256Digest,
}

// Returns one exact lowercase SHA-256 fixture.
fn digest(character: char) -> Sha256Digest {
    Sha256Digest::parse(&character.to_string().repeat(64)).expect("digest")
}

// Serializes one value through the established sorted compact JSON contract.
fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("canonical JSON");
    bytes.push(b'\n');
    bytes
}

// Returns one SHA-256 identity for exact fixture bytes.
fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes))).expect("SHA-256")
}

// Rebinds every derived hash after one deliberate semantic record mutation.
fn rebind_record(value: &mut Value) {
    let result_material = value.get("ttft_cache").map_or_else(
        || value["results"].clone(),
        |ttft_cache| {
            json!({
                "results": value["results"].clone(),
                "ttft_cache": ttft_cache.clone()
            })
        },
    );
    let results_sha256 = sha256(&canonical(&result_material));
    let benchmark_contract_sha256 = sha256(&canonical(&value["benchmark_contract"]));
    value["results_sha256"] = Value::String(results_sha256.as_str().to_string());
    value["benchmark_contract_sha256"] =
        Value::String(benchmark_contract_sha256.as_str().to_string());
    let identity = json!({
        "benchmark_contract_sha256": benchmark_contract_sha256.as_str(),
        "contract": "letsinfer-benchmark-identity-v2",
        "installation_id": value["installation_id"].clone(),
        "results_sha256": results_sha256.as_str(),
        "subject": value["subject"].clone(),
        "timestamp_unix_ns": value["timestamp_unix_ns"].clone()
    });
    value["id"] = Value::String(sha256(&canonical(&identity)).as_str().to_string());
}

// Creates one canonical schema-7 or schema-8 public benchmark record and manager binding.
fn fixture(schema: BenchmarkRecordSchema) -> EvidenceFixture {
    let job_id = OperationId::parse(&"a".repeat(32)).expect("job identity");
    let installation_id = digest('1');
    let target_contract_sha256 = digest('2');
    let request_contract = json!({
        "output_tokens": 128,
        "min_completion_tokens": 128,
        "require_natural_stop": false,
        "temperature": 0,
        "seed": 42042
    });
    let contract = json!({
        "schema_version": 8,
        "suite": "letsinfer-code-prose-v1",
        "generator": {"id": "letsinfer-code-prose", "version": 8},
        "domains": ["code"],
        "execution": {
            "isolation": "fresh-matrix",
            "prefix_state": "shared",
            "samples_per_cell": 1,
            "stream_prefix": "shared-body"
        },
        "tokenizer": {
            "capability": "engine-rendered-chat-count-v1",
            "model_sha256": digest('c').as_str(),
            "engine_payload_sha256": digest('3').as_str(),
            "render_contract": "openai-chat-user-v1"
        },
        "request": request_contract,
        "short": {
            "domains": ["code", "prose"],
            "prompt_tokens": 256,
            "concurrencies": [1, 2, 4],
            "request": {
                "output_tokens": 512,
                "min_completion_tokens": 512,
                "require_natural_stop": false,
                "temperature": 0,
                "seed": 42042
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
                "seed": 42042
            }
        },
        "sample_interval_seconds": 5,
        "cases": [{"id": "32k", "prompt_tokens": 32768, "concurrencies": [1]}]
    });
    let contract_sha256 = sha256(&canonical(&contract));
    let results = json!([{
        "workload": "pp32768,tg128,c1",
        "prompt_domain": "code",
        "prompt_suite": "letsinfer-code-prose-v1",
        "prompt_set_sha256": digest('d').as_str(),
        "actual_prompt_tokens": [32768],
        "aggregate_tps": 1.0,
        "decode_tps": 1.0,
        "ttft_seconds": 1.0,
        "ttft_statistic": "single",
        "ttft_p95_seconds": null,
        "is_prefix_cached": false,
        "max_gpu_usage_percent": null,
        "max_gpu_temperature_c": null,
        "max_cpu_temperature_c": null,
        "max_cpu_usage_percent": null,
        "max_cpu_clock_mhz": -1,
        "max_gpu_clock_mhz": -1,
        "max_vram_clock_mhz": -1,
        "max_system_ram_clock_mhz": -1,
        "max_nvme_usage_percent": -1,
        "max_nvme_temperature_c": -1,
        "max_nvme_read_kib_per_second": -1,
        "max_nvme_write_kib_per_second": -1,
        "telemetry": {
            "interval_seconds": null,
            "columns": [
                "elapsed_seconds",
                "gpu_usage_percent",
                "gpu_temperature_c",
                "cpu_usage_percent",
                "cpu_temperature_c",
                "cpu_clock_mhz",
                "gpu_clock_mhz",
                "vram_clock_mhz",
                "system_ram_clock_mhz",
                "nvme_usage_percent",
                "nvme_temperature_c",
                "nvme_read_kib_per_second",
                "nvme_write_kib_per_second"
            ],
            "samples": []
        }
    }]);
    let ttft_cache = json!({
        "workload": "pp64000,tg1,c1",
        "prompt_domain": "code",
        "prompt_suite": "letsinfer-code-prose-v1",
        "prompt_sha256": digest('e').as_str(),
        "actual_prompt_tokens": 64000,
        "cold_ttft_seconds": 2.0,
        "warm_ttft_seconds": 1.0,
        "cold_cached_prompt_tokens": 0,
        "warm_cached_prompt_tokens": 64000,
        "ttft_speedup_ratio": 2.0,
        "ttft_reduction_percent": 50.0
    });
    let result_material = if schema == BenchmarkRecordSchema::NativeExecutionPayloadV8 {
        json!({"results": results.clone(), "ttft_cache": ttft_cache.clone()})
    } else {
        results.clone()
    };
    let results_sha256 = sha256(&canonical(&result_material));
    let measured = match schema {
        BenchmarkRecordSchema::OciExecutionPayloadV7 => {
            ("measured_engine_oci", "ghcr.io/letsinfer/engine@sha256:")
        }
        BenchmarkRecordSchema::NativeExecutionPayloadV8 => {
            ("measured_engine_kind", "native-archive")
        }
        BenchmarkRecordSchema::CoreLocalFailureV1 => {
            panic!("local failure schema has no successful benchmark fixture")
        }
        BenchmarkRecordSchema::CommunityVerificationV1 => {
            panic!("paired verification schema has a dedicated evidence fixture")
        }
    };
    let measured_value = if measured.0 == "measured_engine_oci" {
        format!("{}{}", measured.1, "4".repeat(64))
    } else {
        measured.1.to_string()
    };
    let mut subject = Map::new();
    subject.insert(
        "candidate_id".to_string(),
        Value::String("engine--owner--model--target".to_string()),
    );
    subject.insert(
        "engine_payload_sha256".to_string(),
        Value::String(digest('3').as_str().to_string()),
    );
    subject.insert(measured.0.to_string(), Value::String(measured_value));
    subject.insert("model_revision".to_string(), Value::String("5".repeat(40)));
    subject.insert(
        "model_uri".to_string(),
        Value::String("hf://owner/model".to_string()),
    );
    subject.insert(
        "runtime_version".to_string(),
        Value::String("1.0.0".to_string()),
    );
    subject.insert("target".to_string(), Value::String("target".to_string()));
    subject.insert(
        "target_contract_sha256".to_string(),
        Value::String(target_contract_sha256.as_str().to_string()),
    );
    let timestamp_unix_ns = 2_000_000_000_u64;
    let mut identity = Map::new();
    identity.insert(
        "benchmark_contract_sha256".to_string(),
        Value::String(contract_sha256.as_str().to_string()),
    );
    identity.insert(
        "contract".to_string(),
        Value::String("letsinfer-benchmark-identity-v2".to_string()),
    );
    identity.insert(
        "installation_id".to_string(),
        Value::String(installation_id.as_str().to_string()),
    );
    identity.insert(
        "results_sha256".to_string(),
        Value::String(results_sha256.as_str().to_string()),
    );
    identity.insert("subject".to_string(), Value::Object(subject.clone()));
    identity.insert(
        "timestamp_unix_ns".to_string(),
        Value::Number(timestamp_unix_ns.into()),
    );
    let evidence_id = sha256(&canonical(&Value::Object(identity)));
    let mut record = json!({
        "schema_version": schema.version(),
        "id": evidence_id.as_str(),
        "installation_id": installation_id.as_str(),
        "timestamp": 2,
        "timestamp_unix_ns": timestamp_unix_ns,
        "subject": Value::Object(subject),
        "benchmark_contract_sha256": contract_sha256.as_str(),
        "results_sha256": results_sha256.as_str(),
        "results": results,
        "benchmark_contract": contract,
    });
    if schema == BenchmarkRecordSchema::NativeExecutionPayloadV8 {
        record["ttft_cache"] = ttft_cache;
    }
    let bytes = canonical(&record);
    let request = BenchmarkRequest::new(
        BenchmarkKind::Local,
        BenchmarkScope::Complete,
        BenchmarkSubject::new(
            InstallationId::parse(installation_id.as_str()).expect("installation"),
            RuntimeInstallationId::parse(&"6".repeat(32)).expect("runtime installation"),
            LogicalModelName::parse("model").expect("model"),
            PlacementGroupId::parse(&"7".repeat(32)).expect("placement group"),
            digest('8'),
            contract_sha256,
            target_contract_sha256,
        ),
    )
    .expect("request");
    EvidenceFixture {
        job_id,
        request,
        outcome: BenchmarkExecutionOutcome::Succeeded {
            raw_evidence_sha256: sha256(&bytes),
            results_sha256: results_sha256.clone(),
            record_schema: schema,
        },
        telemetry: BenchmarkTelemetryReceipt::new(digest('9'), 4),
        restoration: BenchmarkRestoration::new(digest('b')),
        bytes,
        evidence_id,
        results_sha256,
    }
}

// Creates one complete evidence I/O fixture for the requested public schema.
fn evidence_io(fixture: &EvidenceFixture) -> Arc<MockIo> {
    let io = Arc::new(MockIo::default());
    io.directory(SOURCE_ROOT);
    io.directory(Path::new(SOURCE_ROOT).join(fixture.job_id.as_str()));
    io.directory(EVIDENCE_ROOT);
    io.file(
        Path::new(SOURCE_ROOT)
            .join(fixture.job_id.as_str())
            .join("benchmark.json"),
        fixture.bytes.clone(),
    );
    io
}

// Creates one evidence provider over deterministic native I/O.
fn evidence_provider(io: Arc<MockIo>) -> FilesystemBenchmarkEvidenceProvider {
    FilesystemBenchmarkEvidenceProvider::new(
        PathBuf::from(SOURCE_ROOT),
        PathBuf::from(EVIDENCE_ROOT),
        OWNER,
        io,
    )
    .expect("evidence provider")
}

struct CommunityDocumentMock(BenchmarkCommunityVerificationDocument);

impl BenchmarkCommunityVerificationDocumentProvider for CommunityDocumentMock {
    // Returns one injected durable-state decision without reading an outer worker file.
    fn document(
        &self,
        _job_id: &OperationId,
        _request: &BenchmarkRequest,
        _outcome: &BenchmarkExecutionOutcome,
        _telemetry: &BenchmarkTelemetryReceipt,
        _restoration: &BenchmarkRestoration,
    ) -> Result<BenchmarkCommunityVerificationDocument, BenchmarkError> {
        Ok(self.0.clone())
    }
}

// Converts one ordinary fixture into an exact complete verification request.
fn verification_request(fixture: &EvidenceFixture) -> BenchmarkRequest {
    BenchmarkRequest::new(
        BenchmarkKind::verification(
            41,
            BenchmarkGitRevision::parse(&"a".repeat(40)).expect("head"),
            RuntimeCandidateId::parse("engine--owner--model--target").expect("candidate"),
            OperationId::parse(&"d".repeat(32)).expect("transaction"),
            digest('e'),
            digest('0'),
            73,
            digest('f'),
            None,
        )
        .expect("kind"),
        BenchmarkScope::Complete,
        fixture.request.subject().clone(),
    )
    .expect("request")
}

// Adds the exact key and workspace inputs required by the signing provider.
fn prepare_signing_io(io: &MockIo) {
    io.executable(OPENSSL);
    io.directory(WORKSPACE_ROOT);
    io.directory(KEY_ROOT);
    io.file(PRIVATE_KEY, b"private key".to_vec());
    io.file(PUBLIC_KEY, b"public key".to_vec());
}

// Creates one OpenSSL provider over deterministic native I/O and command execution.
fn signing_provider(io: Arc<MockIo>, runner: Arc<CommandMock>) -> OpensslBenchmarkSigningProvider {
    OpensslBenchmarkSigningProvider::new(
        PathBuf::from(OPENSSL),
        PathBuf::from(PRIVATE_KEY),
        PathBuf::from(PUBLIC_KEY),
        PathBuf::from(EVIDENCE_ROOT),
        PathBuf::from(WORKSPACE_ROOT),
        OWNER,
        io,
        runner,
    )
    .expect("signing provider")
}

// Materializes both public record schemas and replays the immutable publication exactly.
#[test]
fn evidence_provider_publishes_and_replays_oci_and_native_records() {
    for schema in [
        BenchmarkRecordSchema::OciExecutionPayloadV7,
        BenchmarkRecordSchema::NativeExecutionPayloadV8,
    ] {
        let fixture = fixture(schema);
        let io = evidence_io(&fixture);
        let provider = evidence_provider(io.clone());
        let receipt = provider
            .finalize(
                &fixture.job_id,
                &fixture.request,
                &fixture.outcome,
                &fixture.telemetry,
                &fixture.restoration,
            )
            .expect("finalize evidence");
        assert_eq!(receipt.evidence_id(), &fixture.evidence_id);
        assert_eq!(receipt.schema(), schema);
        assert_eq!(receipt.byte_count(), fixture.bytes.len() as u64);
        provider
            .verify(&fixture.request, &fixture.outcome, &receipt)
            .expect("verify evidence");
        let replay = provider
            .finalize(
                &fixture.job_id,
                &fixture.request,
                &fixture.outcome,
                &fixture.telemetry,
                &fixture.restoration,
            )
            .expect("replay evidence");
        assert_eq!(replay, receipt);
        assert_eq!(io.event_count("publish"), 1);
        assert_eq!(
            io.bytes(
                &Path::new(EVIDENCE_ROOT).join(format!("{}.json", receipt.evidence_id().as_str()))
            ),
            fixture.bytes
        );
    }
}

// Publishes, replays, verifies, and signs closed Core-local failure evidence distinctly.
#[test]
fn evidence_provider_seals_core_local_failure_without_public_schema_claims() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let io = Arc::new(MockIo::default());
    io.directory(EVIDENCE_ROOT);
    let provider = evidence_provider(io.clone());
    let failure = BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256: None,
        failure: BenchmarkFailure::new(
            BenchmarkFailureCategory::Crash,
            "measuring",
            "worker exited before producing a valid record",
        )
        .expect("failure"),
    };
    let evidence = provider
        .finalize(
            &fixture.job_id,
            &fixture.request,
            &failure,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("local failure evidence");
    assert_eq!(evidence.schema(), BenchmarkRecordSchema::CoreLocalFailureV1);
    provider
        .verify(&fixture.request, &failure, &evidence)
        .expect("verify local failure");
    assert_eq!(
        provider
            .finalize(
                &fixture.job_id,
                &fixture.request,
                &failure,
                &fixture.telemetry,
                &fixture.restoration,
            )
            .expect("failure replay"),
        evidence
    );
    assert_eq!(io.event_count("publish"), 1);

    let destination =
        Path::new(EVIDENCE_ROOT).join(format!("{}.json", evidence.evidence_id().as_str()));
    let value: Value = serde_json::from_slice(&io.bytes(&destination)).expect("local JSON");
    assert_eq!(
        value["schema_name"],
        Value::String("li_benchmark_core_local_failure".to_string())
    );
    assert_eq!(value["schema_version"], json!(1));
    assert_eq!(
        value["outcome"]["kind"],
        Value::String("failed".to_string())
    );
    let cancellation = BenchmarkExecutionOutcome::Cancelled {
        raw_evidence_sha256: None,
    };
    assert_eq!(
        provider.verify(&fixture.request, &cancellation, &evidence),
        Err(BenchmarkError::EvidenceRejected)
    );

    prepare_signing_io(&io);
    let runner = Arc::new(CommandMock::default());
    runner.push(0, b"public DER");
    runner.push(0, &[0x5a; 64]);
    let signing = signing_provider(io.clone(), runner);
    signing
        .sign(&fixture.job_id, &evidence)
        .expect("sign local failure");

    io.file(&destination, b"corrupt\n".to_vec());
    assert_eq!(
        provider.verify(&fixture.request, &failure, &evidence),
        Err(BenchmarkError::EvidenceRejected)
    );
}

// Persists paired outer evidence without an outer worker file and replays it after reconstruction.
#[test]
fn routed_verification_evidence_persists_community_document_without_outer_worker_output() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let request = verification_request(&fixture);
    let outcome = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: digest('c'),
        results_sha256: fixture.results_sha256.clone(),
        record_schema: BenchmarkRecordSchema::CommunityVerificationV1,
    };
    let bytes = canonical_benchmark_json_bytes(&json!({
        "kind": "letsinfer.runtime-verification",
        "schema_version": 1,
    }))
    .expect("community JSON");
    let io = Arc::new(MockIo::default());
    io.directory(EVIDENCE_ROOT);
    let filesystem = Arc::new(evidence_provider(io.clone()));
    let community = Arc::new(CommunityDocumentMock(
        BenchmarkCommunityVerificationDocument::Community(bytes),
    ));
    let routed = RoutedBenchmarkEvidenceProvider::new(
        filesystem.clone(),
        filesystem.clone(),
        community.clone(),
    );
    let receipt = routed
        .finalize(
            &fixture.job_id,
            &request,
            &outcome,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("community evidence");
    assert_eq!(
        receipt.schema(),
        BenchmarkRecordSchema::CommunityVerificationV1
    );
    assert_eq!(receipt.results_sha256(), &fixture.results_sha256);
    routed
        .verify(&request, &outcome, &receipt)
        .expect("verify community evidence");
    assert!(!io.contains(
        &Path::new(SOURCE_ROOT)
            .join(fixture.job_id.as_str())
            .join("benchmark.json")
    ));

    let restarted = RoutedBenchmarkEvidenceProvider::new(filesystem.clone(), filesystem, community);
    assert_eq!(
        restarted
            .finalize(
                &fixture.job_id,
                &request,
                &outcome,
                &fixture.telemetry,
                &fixture.restoration,
            )
            .expect("restart replay"),
        receipt
    );
    assert_eq!(io.event_count("publish"), 1);
}

// Keeps verification failures local until durable parent state says candidate execution started.
#[test]
fn routed_verification_evidence_keeps_pre_candidate_failure_local() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let request = verification_request(&fixture);
    let failure = BenchmarkExecutionOutcome::Failed {
        raw_evidence_sha256: None,
        failure: BenchmarkFailure::new(
            BenchmarkFailureCategory::Crash,
            "baseline",
            "baseline failed before candidate activation",
        )
        .expect("failure"),
    };
    let io = Arc::new(MockIo::default());
    io.directory(EVIDENCE_ROOT);
    let filesystem = Arc::new(evidence_provider(io));
    let routed = RoutedBenchmarkEvidenceProvider::new(
        filesystem.clone(),
        filesystem,
        Arc::new(CommunityDocumentMock(
            BenchmarkCommunityVerificationDocument::LocalFailure,
        )),
    );
    let receipt = routed
        .finalize(
            &fixture.job_id,
            &request,
            &failure,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("local failure");
    assert_eq!(receipt.schema(), BenchmarkRecordSchema::CoreLocalFailureV1);
    routed
        .verify(&request, &failure, &receipt)
        .expect("verify local failure");
}

// Preserves Python's shortest round-trip float spelling at a one-ULP score boundary.
#[test]
fn canonical_json_preserves_python_score_float_identity() {
    assert_eq!(
        canonical_benchmark_json_bytes(&json!({
            "score": 46.669047558312116_f64,
        }))
        .expect("canonical score"),
        b"{\"score\":46.669047558312116}\n"
    );
}

// Rejects changed result identities, noncanonical bytes, and a mismatched execution digest.
#[test]
fn evidence_provider_rejects_content_and_outcome_mismatch() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let io = evidence_io(&fixture);
    let source = Path::new(SOURCE_ROOT)
        .join(fixture.job_id.as_str())
        .join("benchmark.json");
    let mut changed: Value = serde_json::from_slice(&fixture.bytes).expect("JSON");
    changed["results"][0]["aggregate_tps"] = json!(0);
    rebind_record(&mut changed);
    let changed_bytes = canonical(&changed);
    io.file(&source, changed_bytes.clone());
    let changed_outcome = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: sha256(&changed_bytes),
        results_sha256: Sha256Digest::parse(
            changed["results_sha256"].as_str().expect("results digest"),
        )
        .expect("results digest"),
        record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
    };
    assert_eq!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &changed_outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::EvidenceRejected)
    );

    io.file(&source, fixture.bytes[..fixture.bytes.len() - 1].to_vec());
    assert_eq!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::EvidenceRejected)
    );

    io.file(&source, fixture.bytes.clone());
    let wrong_outcome = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: digest('e'),
        results_sha256: fixture.results_sha256.clone(),
        record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
    };
    assert_eq!(
        evidence_provider(io).finalize(
            &fixture.job_id,
            &fixture.request,
            &wrong_outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::EvidenceRejected)
    );

    let io = evidence_io(&fixture);
    let wrong_results = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: sha256(&fixture.bytes),
        results_sha256: digest('f'),
        record_schema: BenchmarkRecordSchema::OciExecutionPayloadV7,
    };
    assert_eq!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &wrong_results,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::EvidenceRejected)
    );
    let wrong_schema = BenchmarkExecutionOutcome::Succeeded {
        raw_evidence_sha256: sha256(&fixture.bytes),
        results_sha256: fixture.results_sha256.clone(),
        record_schema: BenchmarkRecordSchema::NativeExecutionPayloadV8,
    };
    assert_eq!(
        evidence_provider(io).finalize(
            &fixture.job_id,
            &fixture.request,
            &wrong_schema,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::EvidenceRejected)
    );
}

// Rejects symlinks, permissive modes, foreign owners, and multiple hard links.
#[test]
fn evidence_provider_rejects_unsafe_source_metadata() {
    let fixture = fixture(BenchmarkRecordSchema::NativeExecutionPayloadV8);
    let source = Path::new(SOURCE_ROOT)
        .join(fixture.job_id.as_str())
        .join("benchmark.json");
    let unsafe_metadata = [
        BenchmarkEvidenceFileMetadata::new(
            BenchmarkEvidenceEntryKind::SymbolicLink,
            OWNER,
            0o600,
            1,
            fixture.bytes.len() as u64,
        ),
        BenchmarkEvidenceFileMetadata::new(
            BenchmarkEvidenceEntryKind::RegularFile,
            OWNER,
            0o644,
            1,
            fixture.bytes.len() as u64,
        ),
        BenchmarkEvidenceFileMetadata::new(
            BenchmarkEvidenceEntryKind::RegularFile,
            OWNER + 1,
            0o600,
            1,
            fixture.bytes.len() as u64,
        ),
        BenchmarkEvidenceFileMetadata::new(
            BenchmarkEvidenceEntryKind::RegularFile,
            OWNER,
            0o600,
            2,
            fixture.bytes.len() as u64,
        ),
    ];
    for metadata in unsafe_metadata {
        let io = evidence_io(&fixture);
        io.set_metadata(&source, metadata);
        assert!(matches!(
            evidence_provider(io).finalize(
                &fixture.job_id,
                &fixture.request,
                &fixture.outcome,
                &fixture.telemetry,
                &fixture.restoration,
            ),
            Err(BenchmarkError::Provider { .. })
        ));
    }
    assert!(FilesystemBenchmarkEvidenceProvider::new(
        PathBuf::from("relative"),
        PathBuf::from(EVIDENCE_ROOT),
        OWNER,
        Arc::new(MockIo::default()),
    )
    .is_err());
}

// Cleans partial staging and rejects an existing immutable identity with different bytes.
#[test]
fn evidence_provider_rolls_back_partial_io_and_publish_conflict() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let temporary =
        Path::new(EVIDENCE_ROOT).join(format!(".li_benchmark_{}.tmp", fixture.job_id.as_str()));
    let io = evidence_io(&fixture);
    io.partial_write();
    assert!(matches!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::Provider { .. })
    ));
    assert!(!io.contains(&temporary));

    io.partial_read();
    assert!(matches!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::Provider { .. })
    ));
    assert!(!io.contains(&temporary));

    let destination =
        Path::new(EVIDENCE_ROOT).join(format!("{}.json", fixture.evidence_id.as_str()));
    io.fail("sync", 1);
    assert!(matches!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::Provider { .. })
    ));
    assert!(!io.contains(&destination));

    io.file(&destination, b"different canonical bytes\n".to_vec());
    assert_eq!(
        evidence_provider(io.clone()).finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        ),
        Err(BenchmarkError::EvidenceRejected)
    );
    assert!(!io.contains(&temporary));
}

// Uses the exact established OpenSSL argv and cleans all message/signature workspaces.
#[test]
fn signing_provider_signs_verifies_and_replays_exact_evidence() {
    let fixture = fixture(BenchmarkRecordSchema::NativeExecutionPayloadV8);
    let io = evidence_io(&fixture);
    let evidence = evidence_provider(io.clone())
        .finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("evidence");
    prepare_signing_io(&io);
    let partial_runner = Arc::new(CommandMock::default());
    partial_runner.push(0, b"public DER");
    io.partial_write();
    let partial_provider = signing_provider(io.clone(), partial_runner);
    assert!(matches!(
        partial_provider.sign(&fixture.job_id, &evidence),
        Err(BenchmarkError::Provider { .. })
    ));
    assert!(!io.contains(&Path::new(WORKSPACE_ROOT).join(format!(
        ".li_benchmark_message_{}.tmp",
        fixture.job_id.as_str()
    ))));

    let runner = Arc::new(CommandMock::default());
    let public_der = b"deterministic public DER";
    let raw_signature = [0x5a_u8; 64];
    runner.push(0, public_der);
    runner.push(0, &raw_signature);
    runner.push(0, public_der);
    runner.push(0, b"verified");
    runner.push(0, public_der);
    runner.push(0, &raw_signature);
    let provider = signing_provider(io.clone(), runner.clone());

    let signature = provider
        .sign(&fixture.job_id, &evidence)
        .expect("signature");
    assert_eq!(signature.key_id(), &sha256(public_der));
    assert!(provider.verify(&evidence, &signature).expect("verify"));
    assert_eq!(
        provider
            .sign(&fixture.job_id, &evidence)
            .expect("signature replay"),
        signature
    );

    let commands = runner.commands();
    assert_eq!(commands.len(), 6);
    assert_eq!(commands[0].executable(), Path::new(OPENSSL));
    assert_eq!(
        commands[0].arguments(),
        ["pkey", "-pubin", "-in", PUBLIC_KEY, "-outform", "DER"]
    );
    assert_eq!(
        commands[1].arguments(),
        [
            "pkeyutl".to_string(),
            "-sign".to_string(),
            "-inkey".to_string(),
            PRIVATE_KEY.to_string(),
            "-rawin".to_string(),
            "-in".to_string(),
            format!(
                "{WORKSPACE_ROOT}/.li_benchmark_message_{}.tmp",
                fixture.job_id.as_str()
            ),
        ]
    );
    assert_eq!(
        commands[3].arguments(),
        [
            "pkeyutl".to_string(),
            "-verify".to_string(),
            "-pubin".to_string(),
            "-inkey".to_string(),
            PUBLIC_KEY.to_string(),
            "-sigfile".to_string(),
            format!(
                "{WORKSPACE_ROOT}/.li_benchmark_signature_{}.tmp",
                evidence.evidence_id().as_str()
            ),
            "-rawin".to_string(),
            "-in".to_string(),
            format!(
                "{WORKSPACE_ROOT}/.li_benchmark_message_{}.tmp",
                evidence.evidence_id().as_str()
            ),
        ]
    );
    assert!(!io.contains(&Path::new(WORKSPACE_ROOT).join(format!(
        ".li_benchmark_message_{}.tmp",
        fixture.job_id.as_str()
    ))));
    assert!(!io.contains(&Path::new(WORKSPACE_ROOT).join(format!(
        ".li_benchmark_signature_{}.tmp",
        evidence.evidence_id().as_str()
    ))));
}

// Returns false for key/signature mismatch and rejects evidence content drift before OpenSSL.
#[test]
fn signing_provider_rejects_key_signature_and_content_mismatch() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let io = evidence_io(&fixture);
    let evidence = evidence_provider(io.clone())
        .finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("evidence");
    prepare_signing_io(&io);
    let runner = Arc::new(CommandMock::default());
    runner.push(0, b"public DER");
    runner.push(0, b"public DER");
    runner.push(0, b"public DER");
    runner.push(1, b"");
    let provider = signing_provider(io.clone(), runner.clone());
    let foreign = BenchmarkSignature::new(digest('f'), "c2lnbmF0dXJl").expect("signature");
    assert!(!provider.verify(&evidence, &foreign).expect("foreign key"));
    let malformed = BenchmarkSignature::new(sha256(b"public DER"), "a").expect("signature");
    assert!(!provider.verify(&evidence, &malformed).expect("malformed"));
    let mismatched =
        BenchmarkSignature::new(sha256(b"public DER"), &"A".repeat(86)).expect("signature");
    assert!(!provider
        .verify(&evidence, &mismatched)
        .expect("signature mismatch"));

    let destination =
        Path::new(EVIDENCE_ROOT).join(format!("{}.json", evidence.evidence_id().as_str()));
    io.file(&destination, b"changed\n".to_vec());
    assert!(matches!(
        provider.sign(&fixture.job_id, &evidence),
        Err(BenchmarkError::Provider { .. }) | Err(BenchmarkError::EvidenceRejected)
    ));
}

// Redacts command failures and removes temporary message bytes before returning.
#[test]
fn signing_provider_redacts_command_failure_and_cleans_partial_state() {
    let fixture = fixture(BenchmarkRecordSchema::NativeExecutionPayloadV8);
    let io = evidence_io(&fixture);
    let evidence = evidence_provider(io.clone())
        .finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("evidence");
    prepare_signing_io(&io);
    let runner = Arc::new(CommandMock::default());
    runner.push(0, b"public DER");
    runner.fail();
    let provider = signing_provider(io.clone(), runner);
    let error = provider
        .sign(&fixture.job_id, &evidence)
        .expect_err("command failure");
    assert!(matches!(error, BenchmarkError::Provider { .. }));
    assert!(!error.to_string().contains(OPENSSL));
    assert!(!error.to_string().contains(PRIVATE_KEY));
    assert!(!io.contains(&Path::new(WORKSPACE_ROOT).join(format!(
        ".li_benchmark_message_{}.tmp",
        fixture.job_id.as_str()
    ))));
}

// Refuses unsafe key metadata and reports cleanup failure instead of abandoning secret bytes.
#[test]
fn signing_provider_rejects_unsafe_keys_and_cleanup_failure() {
    let fixture = fixture(BenchmarkRecordSchema::OciExecutionPayloadV7);
    let io = evidence_io(&fixture);
    let evidence = evidence_provider(io.clone())
        .finalize(
            &fixture.job_id,
            &fixture.request,
            &fixture.outcome,
            &fixture.telemetry,
            &fixture.restoration,
        )
        .expect("evidence");
    prepare_signing_io(&io);
    io.set_metadata(
        Path::new(PRIVATE_KEY),
        BenchmarkEvidenceFileMetadata::new(
            BenchmarkEvidenceEntryKind::RegularFile,
            OWNER,
            0o600,
            2,
            11,
        ),
    );
    let provider = signing_provider(io.clone(), Arc::new(CommandMock::default()));
    assert!(matches!(
        provider.sign(&fixture.job_id, &evidence),
        Err(BenchmarkError::Provider { .. })
    ));

    io.file(PRIVATE_KEY, b"private key".to_vec());
    let runner = Arc::new(CommandMock::default());
    runner.push(0, b"public DER");
    runner.push(1, b"");
    io.fail("remove", 1);
    let provider = signing_provider(io, runner);
    let error = provider
        .sign(&fixture.job_id, &evidence)
        .expect_err("cleanup failure");
    assert_eq!(
        error,
        BenchmarkError::provider("signing", "signing cleanup failed")
    );
}
