// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use li_benchmark_manager::{
    BenchmarkExecutionArtifact, BenchmarkExecutionLaunch, BenchmarkExecutionRestoration,
    BenchmarkFailure, BenchmarkFailureCategory, BenchmarkProgress, BenchmarkRecordSchema,
    BenchmarkRunPlanProvider, BenchmarkScheduledExecution, BenchmarkScheduledState,
    BenchmarkScheduledTerminal, BenchmarkSchedulerStopReason, BenchmarkScope, BenchmarkStore,
    RunningBenchmark,
};
use li_benchmark_worker::NativeBenchmarkWatchdogInput;
use li_core_interface::{
    EngineDistribution, NativeEngineKind, OperationId, PlacementGroupState, Sha256Digest,
    TechnicalName, UnixMilliseconds,
};
use li_placement_manager::{
    PlacementBenchmarkResetReceipt, PlacementBenchmarkResetRequest, PlacementCredentialReader,
    PlacementManager, PlacementStore,
};
use li_runtime_manager::{RuntimeExecutionManifestProvider, RuntimeInstallationStore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{CoreBenchmarkPortError, CoreBenchmarkTaskPort};

const MAXIMUM_TASK_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;

// Runs and restart-polls the shell-free native benchmark worker through owner-only task files.
pub struct SystemCoreBenchmarkTaskPort {
    worker_executable: PathBuf,
    task_root: PathBuf,
    owner_user_id: u32,
    store: Arc<dyn BenchmarkStore>,
    plans: Arc<dyn BenchmarkRunPlanProvider>,
    runtimes: Arc<dyn RuntimeInstallationStore>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
    placements: Arc<dyn PlacementStore>,
    credentials: Arc<dyn PlacementCredentialReader>,
    placement_manager: Arc<PlacementManager>,
    watchdog: NativeBenchmarkWatchdogInput,
}

impl SystemCoreBenchmarkTaskPort {
    // Creates one production task adapter from exact manager-owned read capabilities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_executable: PathBuf,
        task_root: PathBuf,
        owner_user_id: u32,
        store: Arc<dyn BenchmarkStore>,
        plans: Arc<dyn BenchmarkRunPlanProvider>,
        runtimes: Arc<dyn RuntimeInstallationStore>,
        executions: Arc<dyn RuntimeExecutionManifestProvider>,
        placements: Arc<dyn PlacementStore>,
        credentials: Arc<dyn PlacementCredentialReader>,
        placement_manager: Arc<PlacementManager>,
        watchdog: NativeBenchmarkWatchdogInput,
    ) -> Result<Self, CoreBenchmarkPortError> {
        require_safe_absolute_file(&worker_executable)?;
        require_private_directory(&task_root, owner_user_id)?;
        let executable = fs::symlink_metadata(&worker_executable)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        if !executable.is_file()
            || executable.file_type().is_symlink()
            || executable.mode() & 0o022 != 0
            || executable.mode() & 0o111 == 0
        {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        Ok(Self {
            worker_executable,
            task_root,
            owner_user_id,
            store,
            plans,
            runtimes,
            executions,
            placements,
            credentials,
            placement_manager,
            watchdog,
        })
    }

    // Returns one exact owner-only task directory.
    fn task_directory(&self, job_id: &OperationId) -> PathBuf {
        self.task_root.join(job_id.as_str())
    }

    // Returns the sealed worker input path.
    fn input_file(&self, job_id: &OperationId) -> PathBuf {
        self.task_directory(job_id).join("input.json")
    }

    // Returns the persistent worker status path.
    fn status_file(&self, job_id: &OperationId) -> PathBuf {
        self.task_directory(job_id).join("status.json")
    }

    // Returns the exact task cancellation marker path.
    fn cancellation_file(&self, job_id: &OperationId) -> PathBuf {
        self.task_directory(job_id).join("cancel")
    }

    // Returns the mutable owner-only manager acknowledgment for context-process rotation.
    fn rotation_file(&self, job_id: &OperationId) -> PathBuf {
        self.task_directory(job_id).join("rotation.json")
    }

    // Returns the durable manager request retaining the first observed aggregate revision.
    fn rotation_request_file(&self, job_id: &OperationId) -> PathBuf {
        self.task_directory(job_id).join("rotation_request.json")
    }

    // Returns the evidence source path consumed by FilesystemBenchmarkEvidenceProvider.
    fn output_file(&self, job_id: &OperationId) -> PathBuf {
        self.task_directory(job_id).join("benchmark.json")
    }

    // Creates or validates one exact task directory and sealed input idempotently.
    fn prepare_input(
        &self,
        command: &BenchmarkExecutionLaunch,
    ) -> Result<(), CoreBenchmarkPortError> {
        let directory = self.task_directory(command.job_id());
        ensure_private_directory(&directory, self.owner_user_id)?;
        let path = self.input_file(command.job_id());
        if path.exists() {
            return self.require_existing_input(command, &path);
        }
        let bytes = self.input_bytes(command)?;
        write_new_private_file(&path, &bytes, self.owner_user_id)
    }

    // Revalidates immutable identities before replaying an existing worker input.
    fn require_existing_input(
        &self,
        command: &BenchmarkExecutionLaunch,
        path: &Path,
    ) -> Result<(), CoreBenchmarkPortError> {
        let bytes = read_private_file(path, MAXIMUM_TASK_DOCUMENT_BYTES, self.owner_user_id)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        if value.get("job_id").and_then(Value::as_str) != Some(command.job_id().as_str())
            || value.get("plan_sha256").and_then(Value::as_str)
                != Some(command.plan().plan_sha256().as_str())
            || value
                .get("benchmark_contract_sha256")
                .and_then(Value::as_str)
                != Some(command.plan().benchmark_contract_sha256().as_str())
            || value.get("execution_sha256").and_then(Value::as_str)
                != Some(command.plan().execution_sha256().as_str())
            || value.get("target_contract_sha256").and_then(Value::as_str)
                != Some(command.plan().target_contract_sha256().as_str())
            || value.get("watchdog") != Some(&watchdog_value(&self.watchdog))
        {
            return Err(CoreBenchmarkPortError::Conflict);
        }
        Ok(())
    }

    // Constructs one complete worker input from current exact Runtime and Placement identities.
    fn input_bytes(
        &self,
        command: &BenchmarkExecutionLaunch,
    ) -> Result<Vec<u8>, CoreBenchmarkPortError> {
        let request = command.plan().request();
        let subject = request.subject();
        let runtime = self
            .runtimes
            .read(subject.runtime_installation_id())
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .ok_or(CoreBenchmarkPortError::InvalidState)?
            .installation()
            .clone();
        let execution = self
            .executions
            .manifest(subject.runtime_installation_id())
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        let benchmark = execution
            .benchmark()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let placement = self
            .placements
            .read(subject.placement_group_id())
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let group = placement.record().group();
        let endpoint = group
            .endpoint()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        if group.state() != PlacementGroupState::Running
            || benchmark.contract_sha256() != command.plan().benchmark_contract_sha256()
            || benchmark.target_contract_sha256() != command.plan().target_contract_sha256()
            || runtime.runtime().execution_contract_digest() != command.plan().execution_sha256()
        {
            return Err(CoreBenchmarkPortError::Conflict);
        }
        let endpoint_placement = placement
            .record()
            .placements()
            .iter()
            .find(|placement| placement.placement_id() == endpoint.placement_id())
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let credentials = self
            .credentials
            .existing(endpoint_placement)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        if credentials.credential_id() != endpoint.credential_id()
            || endpoint.ca_credential_id() != Some(credentials.ca_credential_id())
        {
            return Err(CoreBenchmarkPortError::Conflict);
        }
        let token_count = endpoint
            .token_count()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let artifact = runtime
            .artifacts()
            .first()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        if runtime.artifacts().iter().any(|candidate| {
            candidate.uri() != artifact.uri() || candidate.revision() != artifact.revision()
        }) {
            return Err(CoreBenchmarkPortError::InvalidState);
        }
        let payload = runtime
            .runtime()
            .engine_distribution()
            .payload_id()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let (measured_name, measured_value) = measured_engine(
            runtime.runtime().engine_distribution(),
            command.plan().record_schema(),
        )?;
        let mut public_subject = serde_json::Map::new();
        public_subject.insert(
            "candidate_id".to_string(),
            json!(runtime.runtime().candidate_id().as_str()),
        );
        public_subject.insert(
            "runtime_version".to_string(),
            json!(runtime.runtime().version().as_str()),
        );
        public_subject.insert("model_uri".to_string(), json!(artifact.uri().as_str()));
        public_subject.insert(
            "model_revision".to_string(),
            json!(artifact.revision().as_str()),
        );
        public_subject.insert("engine_payload_sha256".to_string(), json!(payload.as_str()));
        public_subject.insert(measured_name.to_string(), json!(measured_value));
        public_subject.insert(
            "target".to_string(),
            json!(runtime.runtime().target_id().as_str()),
        );
        public_subject.insert(
            "target_contract_sha256".to_string(),
            json!(benchmark.target_contract_sha256().as_str()),
        );
        let contract: Value = serde_json::from_slice(benchmark.document())
            .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let selected = match request.scope() {
            BenchmarkScope::Complete => Vec::new(),
            BenchmarkScope::Selected(cells) => {
                cells.iter().map(|cell| cell.as_str().to_string()).collect()
            }
        };
        let timestamp_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .as_nanos();
        let timestamp_unix_ns =
            u64::try_from(timestamp_unix_ns).map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        let value = json!({
            "schema_name": "li-benchmark-worker-input",
            "schema_version": 1,
            "job_id": command.job_id().as_str(),
            "plan_sha256": command.plan().plan_sha256().as_str(),
            "installation_id": subject.installation_id().as_str(),
            "benchmark_contract_sha256": command.plan().benchmark_contract_sha256().as_str(),
            "execution_sha256": command.plan().execution_sha256().as_str(),
            "target_contract_sha256": command.plan().target_contract_sha256().as_str(),
            "record_schema_version": command.plan().record_schema().version(),
            "timestamp_unix_ns": timestamp_unix_ns,
            "model": subject.model().as_str(),
            "route": {
                "placement_group_id": group.placement_group_id().as_str(),
                "endpoint_node_id": endpoint.node_id().as_str(),
                "host": endpoint.address().host().as_str(),
                "port": endpoint.address().port(),
                "owner_user_id": self.owner_user_id,
                "bearer_file": credentials.engine_credential_file(),
                "ca_file": credentials.tls_certificate_file(),
                "token_count_path": token_count.path(),
                "max_active_requests": endpoint.max_active_requests(),
                "max_context_tokens": endpoint.max_context_tokens()
            },
            "output_file": self.output_file(command.job_id()),
            "status_file": self.status_file(command.job_id()),
            "cancellation_file": self.cancellation_file(command.job_id()),
            "rotation_file": self.rotation_file(command.job_id()),
            "watchdog": watchdog_value(&self.watchdog),
            "subject": Value::Object(public_subject),
            "benchmark_contract": contract,
            "selected_cells": selected
        });
        canonical(&value)
    }

    // Starts one direct worker process with no shell, inherited environment, or open standard I/O.
    fn spawn(&self, job_id: &OperationId) -> Result<(), CoreBenchmarkPortError> {
        Command::new(&self.worker_executable)
            .arg("--input")
            .arg(self.input_file(job_id))
            .env_clear()
            .current_dir(&self.task_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|_| CoreBenchmarkPortError::Unavailable)
    }

    // Completes one worker-requested process/store rotation and publishes its exact receipt.
    fn rotate_context(
        &self,
        job_id: &OperationId,
        plan: &li_benchmark_manager::BenchmarkRunPlan,
        status: &Value,
    ) -> Result<(), CoreBenchmarkPortError> {
        let rotation = status
            .get("rotation")
            .and_then(Value::as_object)
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let context = rotation
            .get("context")
            .and_then(Value::as_str)
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let context_index = rotation
            .get("context_index")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let context_count = rotation
            .get("context_count")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let placement_group_id = plan.request().subject().placement_group_id().clone();
        let command = self.rotation_request(
            job_id,
            plan.plan_sha256(),
            placement_group_id,
            context,
            context_index,
            context_count,
        )?;
        if self.existing_rotation_matches(job_id, plan.plan_sha256(), &command)? {
            return Ok(());
        }
        let receipt = self
            .placement_manager
            .reset_for_benchmark(command.clone())
            .map_err(|error| match error {
                li_placement_manager::PlacementError::StoreConflict => {
                    CoreBenchmarkPortError::Conflict
                }
                _ => CoreBenchmarkPortError::Unavailable,
            })?;
        require_rotation_receipt(&receipt, &command)?;
        let bytes = rotation_receipt_bytes(&receipt, job_id, plan.plan_sha256())?;
        write_atomic_private_file(&self.rotation_file(job_id), &bytes, self.owner_user_id)
    }

    // Returns whether the current owner-only acknowledgment already proves this exact command.
    fn existing_rotation_matches(
        &self,
        job_id: &OperationId,
        plan_sha256: &Sha256Digest,
        command: &PlacementBenchmarkResetRequest,
    ) -> Result<bool, CoreBenchmarkPortError> {
        let path = self.rotation_file(job_id);
        if !path.exists() {
            return Ok(false);
        }
        let bytes = read_private_file(&path, 4 * 1024, self.owner_user_id)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        Ok(rotation_document_matches(
            &value,
            job_id,
            plan_sha256,
            command,
        ))
    }

    // Creates or replays one manager reset request before any placement mutation begins.
    fn rotation_request(
        &self,
        job_id: &OperationId,
        plan_sha256: &Sha256Digest,
        placement_group_id: li_core_interface::PlacementGroupId,
        context: &str,
        context_index: u32,
        context_count: u32,
    ) -> Result<PlacementBenchmarkResetRequest, CoreBenchmarkPortError> {
        let reset_id = benchmark_reset_id(
            job_id,
            plan_sha256,
            &placement_group_id,
            context,
            context_index,
            context_count,
        );
        let path = self.rotation_request_file(job_id);
        if path.exists() {
            let bytes = read_private_file(&path, 4 * 1024, self.owner_user_id)?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
            let request = rotation_request_from_value(&value)?;
            let observed_reset_id = benchmark_reset_id(
                job_id,
                plan_sha256,
                request.placement_group_id(),
                request.context(),
                request.context_index(),
                request.context_count(),
            );
            if request.reset_id() != &observed_reset_id
                || request.placement_group_id() != &placement_group_id
                || request.context_count() != context_count
            {
                return Err(CoreBenchmarkPortError::Conflict);
            }
            if request.reset_id() == &reset_id {
                if request.placement_group_id() != &placement_group_id
                    || request.context() != context
                    || request.context_index() != context_index
                    || request.context_count() != context_count
                {
                    return Err(CoreBenchmarkPortError::Conflict);
                }
                return Ok(request);
            }
            if request.context_index().checked_add(1) != Some(context_index)
                || !self.existing_rotation_matches(job_id, plan_sha256, &request)?
            {
                return Err(CoreBenchmarkPortError::Conflict);
            }
        }
        let current = self
            .placements
            .read(&placement_group_id)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let request = PlacementBenchmarkResetRequest::new(
            reset_id,
            placement_group_id,
            current.revision(),
            context,
            context_index,
            context_count,
        )
        .map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let bytes = rotation_request_bytes(&request)?;
        write_atomic_private_file(&path, &bytes, self.owner_user_id)?;
        Ok(request)
    }

    // Reconstructs the exact plan and journal-owned receipts after any Node restart.
    fn current_execution(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
        state: BenchmarkScheduledState,
        started_at: UnixMilliseconds,
    ) -> Result<BenchmarkScheduledExecution, CoreBenchmarkPortError> {
        let journal = self
            .store
            .read(job_id)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let record = journal.record();
        let prepared = record
            .prepared()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let observed_running = record
            .execution()
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        if observed_running.receipt_id() != running.receipt_id() {
            return Err(CoreBenchmarkPortError::Conflict);
        }
        let plan = self
            .plans
            .plan(job_id, record.request())
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        BenchmarkScheduledExecution::new(
            job_id.clone(),
            plan,
            prepared.receipt_id().clone(),
            running.receipt_id().clone(),
            started_at,
            state,
        )
        .map_err(|_| CoreBenchmarkPortError::InvalidState)
    }

    // Reads and validates one persistent worker status document.
    fn status(&self, job_id: &OperationId) -> Result<Option<Value>, CoreBenchmarkPortError> {
        let path = self.status_file(job_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_private_file(&path, 64 * 1024, self.owner_user_id)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let input = read_private_file(
            &self.input_file(job_id),
            MAXIMUM_TASK_DOCUMENT_BYTES,
            self.owner_user_id,
        )?;
        let input: Value =
            serde_json::from_slice(&input).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        require_status_identity(&value, &input, job_id)?;
        Ok(Some(value))
    }

    // Returns the stable first-start time bound into the sealed input record.
    fn started_at(&self, job_id: &OperationId) -> Result<UnixMilliseconds, CoreBenchmarkPortError> {
        let bytes = read_private_file(
            &self.input_file(job_id),
            MAXIMUM_TASK_DOCUMENT_BYTES,
            self.owner_user_id,
        )?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
        let nanoseconds = value
            .get("timestamp_unix_ns")
            .and_then(Value::as_u64)
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        Ok(UnixMilliseconds::new(nanoseconds / 1_000_000))
    }

    // Reattaches a missing worker only when no process holds the sealed input lock.
    fn ensure_running(
        &self,
        job_id: &OperationId,
        allow_initial_spawn: bool,
    ) -> Result<(), CoreBenchmarkPortError> {
        let path = self.input_file(job_id);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
                return Err(CoreBenchmarkPortError::Unavailable);
            }
            if !allow_initial_spawn {
                return Err(CoreBenchmarkPortError::Unavailable);
            }
            self.spawn(job_id)?;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(CoreBenchmarkPortError::Unavailable);
        }
        Ok(())
    }
}

// Encodes the exact Watchdog endpoint and mTLS identities into one sealed worker value.
fn watchdog_value(configuration: &NativeBenchmarkWatchdogInput) -> Value {
    json!({
        "host": configuration.host(),
        "port": configuration.port(),
        "server_name": configuration.server_name(),
        "ca_file": configuration.ca_file(),
        "controller_cert_file": configuration.controller_cert_file(),
        "controller_key_file": configuration.controller_key_file(),
        "timeout_milliseconds": configuration.query_timeout().as_millis()
    })
}

impl CoreBenchmarkTaskPort for SystemCoreBenchmarkTaskPort {
    // Starts or reattaches one exact sealed native worker idempotently.
    fn start(&self, command: &BenchmarkExecutionLaunch) -> Result<(), CoreBenchmarkPortError> {
        self.prepare_input(command)?;
        self.ensure_running(
            command.job_id(),
            !self.status_file(command.job_id()).exists(),
        )
    }

    // Returns running, successful, failed, or cancelled persistent state after any restart.
    fn observe(
        &self,
        job_id: &OperationId,
        running: &RunningBenchmark,
    ) -> Result<BenchmarkScheduledExecution, CoreBenchmarkPortError> {
        let started_at = self.started_at(job_id)?;
        let status = self.status(job_id)?;
        let journal = self
            .store
            .read(job_id)
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
            .ok_or(CoreBenchmarkPortError::InvalidState)?;
        let observed_plan = self
            .plans
            .plan(job_id, journal.record().request())
            .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
        let state = match status
            .as_ref()
            .and_then(|value| value.get("state"))
            .and_then(Value::as_str)
        {
            None | Some("running") => {
                self.ensure_running(job_id, status.is_none())?;
                BenchmarkScheduledState::Running(worker_progress(
                    status.as_ref(),
                    observed_plan.total_cells(),
                )?)
            }
            Some("awaiting_rotation") => {
                let status = status
                    .as_ref()
                    .ok_or(CoreBenchmarkPortError::InvalidState)?;
                self.ensure_running(job_id, false)?;
                self.rotate_context(job_id, &observed_plan, status)?;
                BenchmarkScheduledState::Running(worker_progress(
                    Some(status),
                    observed_plan.total_cells(),
                )?)
            }
            Some("succeeded") => {
                let status = status
                    .as_ref()
                    .ok_or(CoreBenchmarkPortError::InvalidState)?;
                let artifact = status
                    .get("artifact")
                    .and_then(Value::as_object)
                    .ok_or(CoreBenchmarkPortError::InvalidState)?;
                let plan = self
                    .plans
                    .plan(
                        job_id,
                        self.store
                            .read(job_id)
                            .map_err(|_| CoreBenchmarkPortError::Unavailable)?
                            .ok_or(CoreBenchmarkPortError::InvalidState)?
                            .record()
                            .request(),
                    )
                    .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
                let evidence = read_private_file(
                    &self.output_file(job_id),
                    64 * 1024 * 1024,
                    self.owner_user_id,
                )?;
                BenchmarkScheduledState::Terminal(BenchmarkScheduledTerminal::Succeeded(
                    validated_execution_artifact(artifact, &evidence, &plan)?,
                ))
            }
            Some("cancelled") => {
                BenchmarkScheduledState::Terminal(BenchmarkScheduledTerminal::Cancelled {
                    artifact: None,
                })
            }
            Some("failed") => {
                BenchmarkScheduledState::Terminal(BenchmarkScheduledTerminal::Failed {
                    artifact: None,
                    failure: BenchmarkFailure::new(
                        BenchmarkFailureCategory::Crash,
                        "execution",
                        "native benchmark worker failed",
                    )
                    .map_err(|_| CoreBenchmarkPortError::InvalidState)?,
                })
            }
            Some(_) => return Err(CoreBenchmarkPortError::InvalidState),
        };
        self.current_execution(job_id, running, state, started_at)
    }

    // Requests cooperative cancellation through one exact owner-only marker.
    fn request_stop(
        &self,
        job_id: &OperationId,
        _running: &RunningBenchmark,
        _reason: BenchmarkSchedulerStopReason,
    ) -> Result<(), CoreBenchmarkPortError> {
        let path = self.cancellation_file(job_id);
        if path.exists() {
            let existing = read_private_file(&path, 128, self.owner_user_id)?;
            return if std::str::from_utf8(&existing).ok().map(str::trim) == Some(job_id.as_str()) {
                Ok(())
            } else {
                Err(CoreBenchmarkPortError::Conflict)
            };
        }
        write_new_private_file(
            &path,
            format!("{}\n", job_id.as_str()).as_bytes(),
            self.owner_user_id,
        )
    }

    // Removes control-plane task files while retaining canonical evidence for finalization.
    fn cleanup(
        &self,
        command: &BenchmarkExecutionRestoration,
    ) -> Result<(), CoreBenchmarkPortError> {
        remove_task_control_files(&[
            self.input_file(command.job_id()),
            self.status_file(command.job_id()),
            self.cancellation_file(command.job_id()),
            self.rotation_file(command.job_id()),
            self.rotation_request_file(command.job_id()),
        ])
    }
}

// Attempts every task-file removal so one corrupt path cannot retain unrelated control state.
fn remove_task_control_files(paths: &[PathBuf]) -> Result<(), CoreBenchmarkPortError> {
    let mut failed = false;
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => failed = true,
        }
    }
    if failed {
        Err(CoreBenchmarkPortError::Unavailable)
    } else {
        Ok(())
    }
}

// Derives one stable Placement reset idempotency identity from the exact worker boundary.
fn benchmark_reset_id(
    job_id: &OperationId,
    plan_sha256: &Sha256Digest,
    placement_group_id: &li_core_interface::PlacementGroupId,
    context: &str,
    context_index: u32,
    context_count: u32,
) -> Sha256Digest {
    framed_sha256(&[
        "li-benchmark-placement-reset-v1",
        job_id.as_str(),
        plan_sha256.as_str(),
        placement_group_id.as_str(),
        context,
        &context_index.to_string(),
        &context_count.to_string(),
    ])
}

// Encodes one durable pre-mutation Placement reset request.
fn rotation_request_bytes(
    request: &PlacementBenchmarkResetRequest,
) -> Result<Vec<u8>, CoreBenchmarkPortError> {
    canonical(&json!({
        "schema_name": "li-benchmark-placement-reset-request",
        "schema_version": 1,
        "reset_id": request.reset_id().as_str(),
        "placement_group_id": request.placement_group_id().as_str(),
        "expected_revision": request.expected_revision(),
        "context": request.context(),
        "context_index": request.context_index(),
        "context_count": request.context_count()
    }))
}

// Parses one durable reset request without accepting added, missing, or drifted fields.
fn rotation_request_from_value(
    value: &Value,
) -> Result<PlacementBenchmarkResetRequest, CoreBenchmarkPortError> {
    let object = value
        .as_object()
        .ok_or(CoreBenchmarkPortError::InvalidState)?;
    let expected = [
        "schema_name",
        "schema_version",
        "reset_id",
        "placement_group_id",
        "expected_revision",
        "context",
        "context_index",
        "context_count",
    ];
    if object.len() != expected.len()
        || expected.iter().any(|name| !object.contains_key(*name))
        || value.get("schema_name").and_then(Value::as_str)
            != Some("li-benchmark-placement-reset-request")
        || value.get("schema_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    PlacementBenchmarkResetRequest::new(
        digest_value(value, "reset_id")?,
        li_core_interface::PlacementGroupId::parse(
            value
                .get("placement_group_id")
                .and_then(Value::as_str)
                .ok_or(CoreBenchmarkPortError::InvalidState)?,
        )
        .map_err(|_| CoreBenchmarkPortError::InvalidState)?,
        value
            .get("expected_revision")
            .and_then(Value::as_u64)
            .ok_or(CoreBenchmarkPortError::InvalidState)?,
        value
            .get("context")
            .and_then(Value::as_str)
            .ok_or(CoreBenchmarkPortError::InvalidState)?,
        value
            .get("context_index")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CoreBenchmarkPortError::InvalidState)?,
        value
            .get("context_count")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CoreBenchmarkPortError::InvalidState)?,
    )
    .map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Requires one Placement receipt to prove exactly the requested reset boundary.
fn require_rotation_receipt(
    receipt: &PlacementBenchmarkResetReceipt,
    request: &PlacementBenchmarkResetRequest,
) -> Result<(), CoreBenchmarkPortError> {
    if receipt.reset_id() != request.reset_id()
        || receipt.placement_group_id() != request.placement_group_id()
        || receipt.expected_revision() != request.expected_revision()
        || receipt.previous_revision() != request.expected_revision()
        || receipt.context() != request.context()
        || receipt.context_index() != request.context_index()
        || receipt.context_count() != request.context_count()
    {
        return Err(CoreBenchmarkPortError::Conflict);
    }
    Ok(())
}

// Encodes one exact manager receipt for the blocked native worker.
fn rotation_receipt_bytes(
    receipt: &PlacementBenchmarkResetReceipt,
    job_id: &OperationId,
    plan_sha256: &Sha256Digest,
) -> Result<Vec<u8>, CoreBenchmarkPortError> {
    canonical(&json!({
        "schema_name": "li-benchmark-context-rotation",
        "schema_version": 1,
        "job_id": job_id.as_str(),
        "plan_sha256": plan_sha256.as_str(),
        "reset_id": receipt.reset_id().as_str(),
        "placement_group_id": receipt.placement_group_id().as_str(),
        "context": receipt.context(),
        "context_index": receipt.context_index(),
        "context_count": receipt.context_count(),
        "expected_revision": receipt.expected_revision(),
        "previous_revision": receipt.previous_revision(),
        "next_revision": receipt.next_revision(),
        "store_generation_sha256": receipt.store_generation_sha256().as_str(),
        "process_generation_sha256": receipt.process_generation_sha256().as_str(),
        "reset_at_unix_milliseconds": receipt.reset_at().value(),
        "receipt_sha256": receipt.receipt_sha256().as_str()
    }))
}

// Returns whether an existing acknowledgment belongs to this exact reset request.
fn rotation_document_matches(
    value: &Value,
    job_id: &OperationId,
    plan_sha256: &Sha256Digest,
    request: &PlacementBenchmarkResetRequest,
) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let expected_fields = [
        "schema_name",
        "schema_version",
        "job_id",
        "plan_sha256",
        "reset_id",
        "placement_group_id",
        "context",
        "context_index",
        "context_count",
        "expected_revision",
        "previous_revision",
        "next_revision",
        "store_generation_sha256",
        "process_generation_sha256",
        "reset_at_unix_milliseconds",
        "receipt_sha256",
    ];
    let identity_matches = object.len() == expected_fields.len()
        && expected_fields
            .iter()
            .all(|name| object.contains_key(*name))
        && value.get("schema_name").and_then(Value::as_str)
            == Some("li-benchmark-context-rotation")
        && value.get("schema_version").and_then(Value::as_u64) == Some(1)
        && value.get("job_id").and_then(Value::as_str) == Some(job_id.as_str())
        && value.get("plan_sha256").and_then(Value::as_str) == Some(plan_sha256.as_str())
        && value.get("reset_id").and_then(Value::as_str) == Some(request.reset_id().as_str())
        && value.get("placement_group_id").and_then(Value::as_str)
            == Some(request.placement_group_id().as_str())
        && value.get("context").and_then(Value::as_str) == Some(request.context())
        && value.get("context_index").and_then(Value::as_u64)
            == Some(u64::from(request.context_index()))
        && value.get("context_count").and_then(Value::as_u64)
            == Some(u64::from(request.context_count()))
        && value.get("expected_revision").and_then(Value::as_u64)
            == Some(request.expected_revision());
    if !identity_matches {
        return false;
    }
    let Some(next_revision) = value.get("next_revision").and_then(Value::as_u64) else {
        return false;
    };
    let Some(reset_at) = value
        .get("reset_at_unix_milliseconds")
        .and_then(Value::as_u64)
    else {
        return false;
    };
    let Ok(store_generation) = digest_value(value, "store_generation_sha256") else {
        return false;
    };
    let Ok(process_generation) = digest_value(value, "process_generation_sha256") else {
        return false;
    };
    let Ok(receipt) = PlacementBenchmarkResetReceipt::new(
        request,
        request.expected_revision(),
        next_revision,
        store_generation,
        process_generation,
        UnixMilliseconds::new(reset_at),
    ) else {
        return false;
    };
    value.get("previous_revision").and_then(Value::as_u64) == Some(receipt.previous_revision())
        && value.get("receipt_sha256").and_then(Value::as_str)
            == Some(receipt.receipt_sha256().as_str())
}

// Extracts one lowercase SHA-256 from a closed JSON document.
fn digest_value(value: &Value, name: &str) -> Result<Sha256Digest, CoreBenchmarkPortError> {
    Sha256Digest::parse(
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or(CoreBenchmarkPortError::InvalidState)?,
    )
    .map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Hashes ordered text fields with explicit length framing.
fn framed_sha256(fields: &[&str]) -> Sha256Digest {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .expect("SHA-256 formatting is canonical")
}

// Selects the exact public record engine field from the immutable distribution identity.
fn measured_engine(
    distribution: &EngineDistribution,
    schema: BenchmarkRecordSchema,
) -> Result<(&'static str, String), CoreBenchmarkPortError> {
    match (distribution, schema) {
        (
            EngineDistribution::Oci { reference, .. },
            BenchmarkRecordSchema::OciExecutionPayloadV7,
        ) => Ok(("measured_engine_oci", reference.as_str().to_string())),
        (
            EngineDistribution::Native { kind, .. },
            BenchmarkRecordSchema::NativeExecutionPayloadV8,
        ) => Ok((
            "measured_engine_kind",
            match kind {
                NativeEngineKind::NativeArchive => "native-archive",
                NativeEngineKind::PythonStandalone => "python-standalone",
                NativeEngineKind::EmbeddedApplication => "embedded-application",
            }
            .to_string(),
        )),
        _ => Err(CoreBenchmarkPortError::Conflict),
    }
}

// Returns one required canonical digest from a worker artifact object.
fn digest(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Sha256Digest, CoreBenchmarkPortError> {
    Sha256Digest::parse(
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or(CoreBenchmarkPortError::InvalidState)?,
    )
    .map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Validates one worker status against the exact sealed input and benchmark job identity.
fn require_status_identity(
    status: &Value,
    input: &Value,
    job_id: &OperationId,
) -> Result<(), CoreBenchmarkPortError> {
    if status.get("schema_name").and_then(Value::as_str) != Some("li-benchmark-worker-status")
        || status.get("schema_version").and_then(Value::as_u64) != Some(1)
        || status.get("job_id").and_then(Value::as_str) != Some(job_id.as_str())
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    if status.get("plan_sha256").and_then(Value::as_str)
        != input.get("plan_sha256").and_then(Value::as_str)
    {
        return Err(CoreBenchmarkPortError::Conflict);
    }
    Ok(())
}

// Reconstructs bounded monotonic worker progress without inferring unreported cell completion.
fn worker_progress(
    status: Option<&Value>,
    expected_total_cells: u32,
) -> Result<BenchmarkProgress, CoreBenchmarkPortError> {
    let (completed_cells, total_cells) = status
        .and_then(|value| value.get("progress"))
        .filter(|value| !value.is_null())
        .map(|value| {
            let completed = value
                .get("completed_cells")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(CoreBenchmarkPortError::InvalidState)?;
            let total = value
                .get("total_cells")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(CoreBenchmarkPortError::InvalidState)?;
            Ok((completed, total))
        })
        .transpose()?
        .unwrap_or((0, expected_total_cells));
    if total_cells != expected_total_cells {
        return Err(CoreBenchmarkPortError::Conflict);
    }
    BenchmarkProgress::new(
        TechnicalName::parse("measuring").map_err(|_| CoreBenchmarkPortError::InvalidState)?,
        completed_cells,
        total_cells,
    )
    .map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Reconstructs one successful artifact only when the immutable evidence matches every claim.
fn validated_execution_artifact(
    artifact: &serde_json::Map<String, Value>,
    evidence: &[u8],
    plan: &li_benchmark_manager::BenchmarkRunPlan,
) -> Result<BenchmarkExecutionArtifact, CoreBenchmarkPortError> {
    let declared_bytes = artifact
        .get("byte_count")
        .and_then(Value::as_u64)
        .ok_or(CoreBenchmarkPortError::InvalidState)?;
    let completed_cells = artifact
        .get("completed_cells")
        .and_then(Value::as_u64)
        .ok_or(CoreBenchmarkPortError::InvalidState)?;
    let raw_evidence_sha256 = digest(artifact, "raw_evidence_sha256")?;
    if declared_bytes != evidence.len() as u64
        || completed_cells != u64::from(plan.total_cells())
        || raw_evidence_sha256 != sha256(evidence)
    {
        return Err(CoreBenchmarkPortError::Conflict);
    }
    BenchmarkExecutionArtifact::new(
        raw_evidence_sha256,
        digest(artifact, "results_sha256")?,
        plan.benchmark_contract_sha256().clone(),
        plan.execution_sha256().clone(),
        plan.target_contract_sha256().clone(),
        plan.record_schema(),
        declared_bytes,
    )
    .map_err(|_| CoreBenchmarkPortError::InvalidState)
}

// Hashes exact evidence bytes into the shared SHA-256 identity type.
fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 output is canonical")
}

// Encodes compact deterministic JSON with one trailing newline.
fn canonical(value: &Value) -> Result<Vec<u8>, CoreBenchmarkPortError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| CoreBenchmarkPortError::InvalidState)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Creates or validates one exact owner-private task directory.
fn ensure_private_directory(path: &Path, owner_user_id: u32) -> Result<(), CoreBenchmarkPortError> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_private_directory(path, owner_user_id),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| CoreBenchmarkPortError::Unavailable)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
            require_private_directory(path, owner_user_id)
        }
        Err(_) => Err(CoreBenchmarkPortError::Unavailable),
    }
}

// Requires one real exact-owner 0700 directory.
fn require_private_directory(
    path: &Path,
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkPortError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    Ok(())
}

// Writes one new exact-owner 0600 file without following aliases.
fn write_new_private_file(
    path: &Path,
    bytes: &[u8],
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkPortError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_TASK_DOCUMENT_BYTES {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    file.write_all(bytes)
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    file.sync_all()
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    if metadata.uid() != owner_user_id || metadata.mode() & 0o777 != 0o600 {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    Ok(())
}

// Atomically replaces one task-owned mutable document through a new owner-only file.
fn write_atomic_private_file(
    path: &Path,
    bytes: &[u8],
    owner_user_id: u32,
) -> Result<(), CoreBenchmarkPortError> {
    let parent = path.parent().ok_or(CoreBenchmarkPortError::InvalidState)?;
    require_private_directory(parent, owner_user_id)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(CoreBenchmarkPortError::InvalidState)?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    write_new_private_file(&temporary, bytes, owner_user_id)?;
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(CoreBenchmarkPortError::Unavailable);
    }
    OpenOptions::new()
        .read(true)
        .open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CoreBenchmarkPortError::Unavailable)
}

// Reads one bounded exact-owner 0600 single-link regular file.
fn read_private_file(
    path: &Path,
    maximum_bytes: usize,
    owner_user_id: u32,
) -> Result<Vec<u8>, CoreBenchmarkPortError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != owner_user_id
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes as u64
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| CoreBenchmarkPortError::Unavailable)?;
    Ok(bytes)
}

// Requires one normalization-free absolute executable path.
fn require_safe_absolute_file(path: &Path) -> Result<(), CoreBenchmarkPortError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || path.file_name().is_none()
    {
        return Err(CoreBenchmarkPortError::InvalidState);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Returns one ordinary immutable OCI distribution for schema-selection tests.
    fn oci_distribution() -> EngineDistribution {
        EngineDistribution::oci(
            li_core_interface::RuntimeSource::parse(
                "docker://registry.example/engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("OCI reference"),
            Sha256Digest::parse(&"a".repeat(64)).expect("OCI digest"),
            None,
            Some(Sha256Digest::parse(&"b".repeat(64)).expect("payload digest")),
        )
    }

    // Returns one ordinary immutable native distribution for schema-selection tests.
    fn native_distribution() -> EngineDistribution {
        EngineDistribution::native(
            NativeEngineKind::NativeArchive,
            li_core_interface::PlatformIdentity::new(
                li_core_interface::OperatingSystem::Macos,
                li_core_interface::CpuArchitecture::Arm64,
            ),
            Sha256Digest::parse(&"c".repeat(64)).expect("payload digest"),
            li_core_interface::ArtifactRevision::parse(&"d".repeat(40)).expect("revision"),
        )
    }

    // Returns one exact two-cell native run plan for worker-artifact verification tests.
    fn native_plan() -> li_benchmark_manager::BenchmarkRunPlan {
        let request = li_benchmark_manager::BenchmarkRequest::new(
            li_benchmark_manager::BenchmarkKind::Local,
            BenchmarkScope::Complete,
            li_benchmark_manager::BenchmarkSubject::new(
                li_core_interface::InstallationId::parse(&"1".repeat(64))
                    .expect("Core installation"),
                li_core_interface::RuntimeInstallationId::parse(&"2".repeat(32))
                    .expect("Runtime installation"),
                li_core_interface::LogicalModelName::parse("model").expect("model"),
                li_core_interface::PlacementGroupId::parse(&"3".repeat(32))
                    .expect("placement group"),
                Sha256Digest::parse(&"4".repeat(64)).expect("execution"),
                Sha256Digest::parse(&"5".repeat(64)).expect("benchmark"),
                Sha256Digest::parse(&"6".repeat(64)).expect("target"),
            ),
        )
        .expect("request");
        li_benchmark_manager::BenchmarkRunPlan::new(
            &request,
            BenchmarkRecordSchema::NativeExecutionPayloadV8,
            2,
            10_000,
            1_000,
            1_000,
        )
        .expect("plan")
    }

    // Seals every Watchdog endpoint and trust field required by the native worker input.
    #[test]
    fn worker_watchdog_value_is_complete_and_exact() {
        let configuration = NativeBenchmarkWatchdogInput::new(
            "127.0.0.1".to_string(),
            9_445,
            "node.local".to_string(),
            PathBuf::from("/trust/watchdog-ca.pem"),
            PathBuf::from("/trust/watchdog-controller.pem"),
            PathBuf::from("/trust/watchdog-controller.key"),
            std::time::Duration::from_millis(4_000),
        )
        .expect("Watchdog input");

        assert_eq!(
            watchdog_value(&configuration),
            json!({
                "host": "127.0.0.1",
                "port": 9_445,
                "server_name": "node.local",
                "ca_file": "/trust/watchdog-ca.pem",
                "controller_cert_file": "/trust/watchdog-controller.pem",
                "controller_key_file": "/trust/watchdog-controller.key",
                "timeout_milliseconds": 4_000
            })
        );
    }

    // Binds each public record schema to exactly one compatible immutable Engine identity.
    #[test]
    fn measured_engine_rejects_distribution_schema_drift() {
        let oci = oci_distribution();
        let native = native_distribution();
        assert!(matches!(
            measured_engine(&oci, BenchmarkRecordSchema::OciExecutionPayloadV7),
            Ok(("measured_engine_oci", _))
        ));
        assert_eq!(
            measured_engine(&native, BenchmarkRecordSchema::NativeExecutionPayloadV8),
            Ok(("measured_engine_kind", "native-archive".to_string()))
        );
        assert_eq!(
            measured_engine(&oci, BenchmarkRecordSchema::NativeExecutionPayloadV8),
            Err(CoreBenchmarkPortError::Conflict)
        );
        assert_eq!(
            measured_engine(&native, BenchmarkRecordSchema::OciExecutionPayloadV7),
            Err(CoreBenchmarkPortError::Conflict)
        );
    }

    // Rejects absent, foreign, or drifted worker-status identities before lifecycle polling.
    #[test]
    fn worker_status_requires_exact_job_schema_and_sealed_plan() {
        let job_id = OperationId::parse(&"a".repeat(32)).expect("job");
        let input = json!({"plan_sha256": "b".repeat(64)});
        let status = json!({
            "schema_name": "li-benchmark-worker-status",
            "schema_version": 1,
            "job_id": job_id.as_str(),
            "plan_sha256": "b".repeat(64),
            "state": "running"
        });
        assert_eq!(require_status_identity(&status, &input, &job_id), Ok(()));

        for mutation in [
            ("schema_name", json!("foreign")),
            ("schema_version", json!(2)),
            ("job_id", json!("c".repeat(32))),
        ] {
            let mut drifted = status.clone();
            drifted[mutation.0] = mutation.1;
            assert_eq!(
                require_status_identity(&drifted, &input, &job_id),
                Err(CoreBenchmarkPortError::InvalidState)
            );
        }
        let mut drifted = status;
        drifted["plan_sha256"] = json!("d".repeat(64));
        assert_eq!(
            require_status_identity(&drifted, &input, &job_id),
            Err(CoreBenchmarkPortError::Conflict)
        );
    }

    // Preserves exact worker progress and rejects malformed or plan-divergent cell counts.
    #[test]
    fn worker_progress_is_exact_bounded_and_plan_bound() {
        let missing = worker_progress(None, 4).expect("missing progress");
        assert_eq!(missing.completed_cells(), 0);
        assert_eq!(missing.total_cells(), 4);
        let status = json!({
            "progress": {"completed_cells": 3, "total_cells": 4}
        });
        let observed = worker_progress(Some(&status), 4).expect("reported progress");
        assert_eq!(observed.completed_cells(), 3);
        assert_eq!(observed.total_cells(), 4);

        let divergent = json!({
            "progress": {"completed_cells": 3, "total_cells": 5}
        });
        assert_eq!(
            worker_progress(Some(&divergent), 4),
            Err(CoreBenchmarkPortError::Conflict)
        );
        for invalid in [
            json!({"progress": {"completed_cells": 5, "total_cells": 4}}),
            json!({"progress": {"completed_cells": "3", "total_cells": 4}}),
            json!({"progress": []}),
        ] {
            assert_eq!(
                worker_progress(Some(&invalid), 4),
                Err(CoreBenchmarkPortError::InvalidState)
            );
        }
    }

    // Rejects evidence path, byte count, cell count, and content-hash drift before finalization.
    #[test]
    fn successful_worker_artifact_is_bound_to_exact_evidence_and_plan() {
        let evidence = b"{\"schema_version\":8}\n";
        let plan = native_plan();
        let artifact = json!({
            "raw_evidence_sha256": sha256(evidence).as_str(),
            "results_sha256": "7".repeat(64),
            "byte_count": evidence.len(),
            "completed_cells": plan.total_cells()
        });
        let artifact = artifact.as_object().expect("artifact");
        assert!(validated_execution_artifact(artifact, evidence, &plan).is_ok());

        for mutation in [
            ("raw_evidence_sha256", json!("8".repeat(64))),
            ("byte_count", json!(evidence.len() + 1)),
            ("completed_cells", json!(plan.total_cells() - 1)),
        ] {
            let mut drifted = Value::Object(artifact.clone());
            drifted[mutation.0] = mutation.1;
            assert_eq!(
                validated_execution_artifact(
                    drifted.as_object().expect("drifted artifact"),
                    evidence,
                    &plan,
                ),
                Err(CoreBenchmarkPortError::Conflict)
            );
        }
        assert_eq!(
            validated_execution_artifact(artifact, b"different\n", &plan),
            Err(CoreBenchmarkPortError::Conflict)
        );
    }

    // Enforces normalized absolute worker paths before any native process can be started.
    #[test]
    fn worker_path_rejects_relative_and_normalized_aliases() {
        assert_eq!(
            require_safe_absolute_file(Path::new("li_benchmark_worker")),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        assert_eq!(
            require_safe_absolute_file(Path::new("/private/tmp/../li_benchmark_worker")),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        assert_eq!(
            require_safe_absolute_file(Path::new("/private/tmp/li_benchmark_worker")),
            Ok(())
        );
    }

    // Refuses mode, link-count, alias, size, and replacement drift for task-owned files.
    #[test]
    fn private_task_file_io_is_exact_and_non_replacing() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("directory mode");
        let owner_user_id = fs::metadata(temporary.path()).expect("owner").uid();
        let path = temporary.path().join("input.json");
        write_new_private_file(&path, b"{}\n", owner_user_id).expect("private input");
        assert_eq!(
            read_private_file(&path, 32, owner_user_id).expect("private read"),
            b"{}\n"
        );
        assert_eq!(
            write_new_private_file(&path, b"replacement\n", owner_user_id),
            Err(CoreBenchmarkPortError::Unavailable)
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("weak mode");
        assert_eq!(
            read_private_file(&path, 32, owner_user_id),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
        let alias = temporary.path().join("alias.json");
        fs::hard_link(&path, &alias).expect("hard link");
        assert_eq!(
            read_private_file(&path, 32, owner_user_id),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        fs::remove_file(alias).expect("remove hard link");
        assert_eq!(
            read_private_file(&path, 2, owner_user_id),
            Err(CoreBenchmarkPortError::InvalidState)
        );

        let symbolic = temporary.path().join("symbolic.json");
        std::os::unix::fs::symlink(&path, &symbolic).expect("symbolic link");
        assert_eq!(
            read_private_file(&symbolic, 32, owner_user_id),
            Err(CoreBenchmarkPortError::Unavailable)
        );
        assert_eq!(
            write_new_private_file(&temporary.path().join("empty"), b"", owner_user_id),
            Err(CoreBenchmarkPortError::InvalidState)
        );
    }

    // Requires task roots to remain exact-owner directories with no group or world access.
    #[test]
    fn private_task_directory_rejects_mode_and_alias_drift() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let owner_user_id = fs::metadata(temporary.path()).expect("owner").uid();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("directory mode");
        assert_eq!(
            require_private_directory(temporary.path(), owner_user_id),
            Ok(())
        );
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o750))
            .expect("weak mode");
        assert_eq!(
            require_private_directory(temporary.path(), owner_user_id),
            Err(CoreBenchmarkPortError::InvalidState)
        );
        let parent = tempfile::tempdir().expect("alias parent");
        let alias = parent.path().join("tasks");
        std::os::unix::fs::symlink(temporary.path(), &alias).expect("directory alias");
        assert_eq!(
            require_private_directory(&alias, owner_user_id),
            Err(CoreBenchmarkPortError::InvalidState)
        );
    }

    // Binds the Application handshake to the complete Placement reset receipt and request replay.
    #[test]
    fn rotation_handshake_rejects_request_or_native_generation_drift() {
        let job_id = OperationId::parse(&"a".repeat(32)).expect("job");
        let plan_sha256 = Sha256Digest::parse(&"b".repeat(64)).expect("plan");
        let group = li_core_interface::PlacementGroupId::parse(&"c".repeat(32)).expect("group");
        let reset_id = benchmark_reset_id(&job_id, &plan_sha256, &group, "short", 1, 2);
        let request = PlacementBenchmarkResetRequest::new(reset_id, group, 7, "short", 1, 2)
            .expect("request");
        let receipt = PlacementBenchmarkResetReceipt::new(
            &request,
            7,
            11,
            Sha256Digest::parse(&"d".repeat(64)).expect("store"),
            Sha256Digest::parse(&"e".repeat(64)).expect("process"),
            UnixMilliseconds::new(900),
        )
        .expect("receipt");
        let request_value: Value =
            serde_json::from_slice(&rotation_request_bytes(&request).expect("request bytes"))
                .expect("request JSON");
        assert_eq!(
            rotation_request_from_value(&request_value).expect("request replay"),
            request
        );
        let bytes = rotation_receipt_bytes(&receipt, &job_id, &plan_sha256).expect("ack");
        let value: Value = serde_json::from_slice(&bytes).expect("ack JSON");
        assert!(rotation_document_matches(
            &value,
            &job_id,
            &plan_sha256,
            &request,
        ));

        for name in [
            "job_id",
            "plan_sha256",
            "reset_id",
            "placement_group_id",
            "context",
            "context_index",
            "context_count",
            "expected_revision",
            "previous_revision",
            "next_revision",
            "store_generation_sha256",
            "process_generation_sha256",
            "reset_at_unix_milliseconds",
            "receipt_sha256",
        ] {
            let mut drifted = value.clone();
            drifted[name] = match name {
                "job_id" => json!("f".repeat(32)),
                "context" => json!("32k"),
                "context_index" => json!(2),
                "context_count" => json!(3),
                "expected_revision" | "previous_revision" => json!(8),
                "next_revision" => json!(12),
                "reset_at_unix_milliseconds" => json!(901),
                "placement_group_id" => json!("f".repeat(32)),
                _ => json!("f".repeat(64)),
            };
            assert!(
                !rotation_document_matches(&drifted, &job_id, &plan_sha256, &request,),
                "{name} drift was admitted"
            );
        }
        let mut added = value;
        added["foreign"] = json!(true);
        assert!(!rotation_document_matches(
            &added,
            &job_id,
            &plan_sha256,
            &request,
        ));
    }

    // Attempts every cleanup path and remains idempotent after one corrupt entry is repaired.
    #[test]
    fn task_cleanup_contains_one_path_failure_without_retaining_other_files() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let invalid = temporary.path().join("input.json");
        let removable = temporary.path().join("status.json");
        fs::create_dir(&invalid).expect("invalid control path");
        fs::write(&removable, b"status\n").expect("removable control file");
        assert_eq!(
            remove_task_control_files(&[invalid.clone(), removable.clone()]),
            Err(CoreBenchmarkPortError::Unavailable)
        );
        assert!(!removable.exists());
        fs::remove_dir(invalid).expect("repair invalid path");
        assert_eq!(remove_task_control_files(&[removable]), Ok(()),);
    }
}
