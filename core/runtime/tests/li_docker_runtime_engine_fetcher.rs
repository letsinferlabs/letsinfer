// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use li_core_interface::{
    ArtifactName, ArtifactRevision, ArtifactUri, ByteCount, CpuArchitecture, EngineDistribution,
    EvidenceLabel, LogicalModelName, MemoryTopology, ModelArtifact, ModelArtifactFormat,
    NativeEngineKind, OperatingSystem, PlatformIdentity, RuntimeCandidateId, RuntimeIdentity,
    RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TechnicalName,
};
use li_runtime_manager::{
    DockerRuntimeEngineFetcher, DockerRuntimeEngineIo, RuntimeAcceleratorVendor, RuntimeCandidate,
    RuntimeEngineArtifactFetcher, RuntimeEngineCommand, RuntimeEngineCommandOutput,
    RuntimeEngineCommandRunner, RuntimeError, RuntimeExactCandidateArtifacts,
    RuntimeExactEngineArtifact, RuntimeExactEngineCleanup, RuntimeExactEngineOwnership,
    RuntimeTarget, SystemDockerRuntimeEngineIo, SystemRuntimeEngineCommandRunner,
};

// Returns one exact model artifact required by every candidate fixture.
fn model_artifact() -> ModelArtifact {
    ModelArtifact::new(
        ArtifactName::parse("model").expect("name"),
        ArtifactUri::parse("hf://FixtureOrg/FixtureModel").expect("URI"),
        ArtifactRevision::parse(&"1".repeat(40)).expect("revision"),
        ModelArtifactFormat::HuggingFaceSnapshot,
    )
}

// Returns one exact Linux OCI candidate for the selected architecture.
fn oci_candidate(architecture: CpuArchitecture) -> RuntimeCandidate {
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
            Sha256Digest::parse(&"2".repeat(64)).expect("runtime digest"),
            Sha256Digest::parse(&"3".repeat(64)).expect("manifest digest"),
            Sha256Digest::parse(&"4".repeat(64)).expect("execution digest"),
        )
        .expect("runtime"),
        vec![model_artifact()],
        RuntimeTarget::new(
            OperatingSystem::Linux,
            architecture,
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

// Returns one native macOS candidate rejected by the Docker provider.
fn native_candidate() -> RuntimeCandidate {
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
            EngineDistribution::native(
                NativeEngineKind::NativeArchive,
                PlatformIdentity::new(OperatingSystem::Macos, CpuArchitecture::Arm64),
                Sha256Digest::parse(&"6".repeat(64)).expect("payload"),
                ArtifactRevision::parse(&"7".repeat(40)).expect("source revision"),
            ),
            Sha256Digest::parse(&"2".repeat(64)).expect("runtime digest"),
            Sha256Digest::parse(&"3".repeat(64)).expect("manifest digest"),
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
    .expect("candidate")
}

// Mocks ordered Docker command results and records exact argv.
struct MockRunner {
    outputs: Mutex<VecDeque<Result<RuntimeEngineCommandOutput, RuntimeError>>>,
    commands: Mutex<Vec<RuntimeEngineCommand>>,
}

impl MockRunner {
    // Creates one ordered Docker command fixture.
    fn new(outputs: Vec<RuntimeEngineCommandOutput>) -> Self {
        Self {
            outputs: Mutex::new(outputs.into_iter().map(Ok).collect()),
            commands: Mutex::new(Vec::new()),
        }
    }
}

impl RuntimeEngineCommandRunner for MockRunner {
    // Returns the next configured process result.
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

// Models exact Docker image/tag ownership and optional post-mutation response loss.
struct OwnershipRunner {
    state: Mutex<OwnershipState>,
    commands: Mutex<Vec<RuntimeEngineCommand>>,
}

// Stores the deterministic Docker state consumed by exact ownership tests.
struct OwnershipState {
    expected_identity: String,
    config_present: bool,
    tags: BTreeMap<String, String>,
    local_tag: String,
    lose_load_response: bool,
    lose_tag_response: bool,
}

impl OwnershipRunner {
    // Creates one injected Docker state with no command history.
    fn new(state: OwnershipState) -> Self {
        Self {
            state: Mutex::new(state),
            commands: Mutex::new(Vec::new()),
        }
    }

    // Rebinds one tag to a concurrent foreign identity before cleanup.
    fn drift_tag(&self, reference: &str) {
        self.state
            .lock()
            .expect("ownership state")
            .tags
            .insert(reference.to_string(), format!("sha256:{}", "f".repeat(64)));
    }
}

impl RuntimeEngineCommandRunner for OwnershipRunner {
    // Applies one exact inspect/load/tag/remove command before optionally losing its response.
    fn run(
        &self,
        command: &RuntimeEngineCommand,
        _maximum_stdout_bytes: usize,
    ) -> Result<RuntimeEngineCommandOutput, RuntimeError> {
        self.commands
            .lock()
            .expect("commands")
            .push(command.clone());
        let arguments = command.arguments();
        let mut state = self.state.lock().expect("ownership state");
        match arguments.first().map(String::as_str) {
            Some("image") if arguments.get(1).map(String::as_str) == Some("inspect") => {
                let reference = arguments.get(2).expect("inspect reference");
                let identity = if reference == &state.expected_identity {
                    state
                        .config_present
                        .then(|| state.expected_identity.clone())
                } else {
                    state.tags.get(reference).cloned()
                };
                Ok(identity.map_or_else(
                    || RuntimeEngineCommandOutput::new(1, Vec::new()),
                    |identity| {
                        RuntimeEngineCommandOutput::new(
                            0,
                            format!("{identity}|linux/arm64\n").into_bytes(),
                        )
                    },
                ))
            }
            Some("load") => {
                state.config_present = true;
                let local_tag = state.local_tag.clone();
                let expected_identity = state.expected_identity.clone();
                state.tags.insert(local_tag, expected_identity);
                if std::mem::take(&mut state.lose_load_response) {
                    Err(RuntimeError::EngineAcquisitionUnavailable)
                } else {
                    Ok(RuntimeEngineCommandOutput::new(
                        0,
                        b"Loaded image\n".to_vec(),
                    ))
                }
            }
            Some("tag") => {
                let source = arguments.get(1).expect("tag source");
                let destination = arguments.get(2).expect("tag destination");
                let identity = state
                    .tags
                    .get(source)
                    .cloned()
                    .ok_or(RuntimeError::EngineAcquisitionUnavailable)?;
                state.tags.insert(destination.clone(), identity);
                if std::mem::take(&mut state.lose_tag_response) {
                    Err(RuntimeError::EngineAcquisitionUnavailable)
                } else {
                    Ok(RuntimeEngineCommandOutput::new(0, Vec::new()))
                }
            }
            Some("image") if arguments.get(1).map(String::as_str) == Some("rm") => {
                for reference in arguments.iter().skip(2) {
                    if reference == &state.expected_identity {
                        if state
                            .tags
                            .values()
                            .any(|identity| identity == &state.expected_identity)
                        {
                            return Ok(RuntimeEngineCommandOutput::new(1, Vec::new()));
                        }
                        state.config_present = false;
                    } else {
                        state.tags.remove(reference);
                    }
                }
                Ok(RuntimeEngineCommandOutput::new(0, Vec::new()))
            }
            _ => Err(RuntimeError::EngineAcquisitionInvalid),
        }
    }
}

// Wraps real receipt I/O and fails one named boundary.
struct FailingIo {
    system: SystemDockerRuntimeEngineIo,
    step: Mutex<Option<&'static str>>,
    clears: AtomicUsize,
}

impl FailingIo {
    // Creates one real-I/O wrapper with no configured failure.
    fn new() -> Self {
        Self {
            system: SystemDockerRuntimeEngineIo,
            step: Mutex::new(None),
            clears: AtomicUsize::new(0),
        }
    }

    // Returns whether one exact I/O boundary is configured to fail.
    fn fails(&self, step: &'static str) -> bool {
        self.step.lock().expect("step").as_ref() == Some(&step)
    }
}

impl DockerRuntimeEngineIo for FailingIo {
    // Prepares one destination or returns the configured failure.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        if self.fails("prepare") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.prepare_destination(destination)
    }

    // Writes one receipt or returns the configured failure.
    fn write_receipt(&self, destination: &Path, receipt: &[u8]) -> Result<(), RuntimeError> {
        if self.fails("receipt") {
            return Err(RuntimeError::EngineAcquisitionUnavailable);
        }
        self.system.write_receipt(destination, receipt)
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

// Creates one empty owner-only Engine destination.
fn destination(directory: &tempfile::TempDir) -> PathBuf {
    let destination = directory.path().join("engine");
    fs::create_dir(&destination).expect("destination");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("private destination");
    }
    destination
}

// Creates one Docker provider with retained deterministic boundaries.
fn fetcher(
    directory: &tempfile::TempDir,
    outputs: Vec<RuntimeEngineCommandOutput>,
) -> (DockerRuntimeEngineFetcher, Arc<MockRunner>, Arc<FailingIo>) {
    let runner = Arc::new(MockRunner::new(outputs));
    let io = Arc::new(FailingIo::new());
    let fetcher = DockerRuntimeEngineFetcher::new(
        PathBuf::from("/usr/bin/docker"),
        directory.path().to_path_buf(),
        vec![("HOME".to_string(), "/home/fixture".to_string())],
        runner.clone(),
        io.clone(),
    )
    .expect("fetcher");
    (fetcher, runner, io)
}

// Returns the fixture candidate Engine reference.
fn candidate_engine_reference() -> String {
    let candidate = oci_candidate(CpuArchitecture::Arm64);
    let EngineDistribution::Oci { reference, .. } = candidate.runtime().engine_distribution()
    else {
        panic!("fixture Engine is not OCI");
    };
    reference.as_str().to_string()
}

// Creates one exact-ownership Docker provider around an injected local image state.
fn ownership_fetcher(
    directory: &tempfile::TempDir,
    config_present: bool,
    references: &[&str],
    lose_load_response: bool,
    lose_tag_response: bool,
) -> (DockerRuntimeEngineFetcher, Arc<OwnershipRunner>) {
    let expected_identity = format!("sha256:{}", "6".repeat(64));
    let runner = Arc::new(OwnershipRunner::new(OwnershipState {
        expected_identity: expected_identity.clone(),
        config_present,
        tags: references
            .iter()
            .map(|reference| ((*reference).to_string(), expected_identity.clone()))
            .collect(),
        local_tag: "li-verifier/candidate:fixture".to_string(),
        lose_load_response,
        lose_tag_response,
    }));
    let fetcher = DockerRuntimeEngineFetcher::new(
        PathBuf::from("/usr/bin/docker"),
        directory.path().to_path_buf(),
        Vec::new(),
        runner.clone(),
        Arc::new(FailingIo::new()),
    )
    .expect("ownership fetcher");
    (fetcher, runner)
}

// Returns one retained built-OCI closure and its path-free cleanup identity.
fn exact_ownership_inputs(
    directory: &tempfile::TempDir,
) -> (RuntimeExactCandidateArtifacts, RuntimeExactEngineCleanup) {
    let archive = directory.path().join("engine.oci.tar");
    fs::write(&archive, b"fixture archive bytes").expect("archive");
    let config_digest = Sha256Digest::parse(&"6".repeat(64)).expect("config");
    let local_tag = "li-verifier/candidate:fixture".to_string();
    let artifacts = RuntimeExactCandidateArtifacts::new(
        directory.path().join("runtime.letsinfer"),
        RuntimeExactEngineArtifact::BuiltOci {
            archive_file: archive,
            config_digest: config_digest.clone(),
            local_tag: local_tag.clone(),
        },
        Sha256Digest::parse(&"9".repeat(64)).expect("closure"),
    )
    .expect("artifacts");
    let cleanup =
        RuntimeExactEngineCleanup::new(candidate_engine_reference(), local_tag, config_digest)
            .expect("cleanup");
    (artifacts, cleanup)
}

// Prepares and completes one exact built-OCI acquisition through the public provider contract.
fn acquire_exact(
    fetcher: &DockerRuntimeEngineFetcher,
    artifacts: &RuntimeExactCandidateArtifacts,
    cleanup: &RuntimeExactEngineCleanup,
    destination: &Path,
) -> RuntimeExactEngineOwnership {
    let prepared = fetcher.prepare_exact(cleanup).expect("prepare ownership");
    fetcher
        .fetch_exact(
            &oci_candidate(CpuArchitecture::Arm64),
            artifacts,
            Some(&prepared),
            Path::new("/runtime"),
            destination,
        )
        .expect("acquire exact")
        .expect("ownership receipt")
}

// Reuses an exact local image and records one deterministic verified receipt.
#[test]
fn existing_exact_image_is_verified_without_pull() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, runner, _) = fetcher(
        &directory,
        vec![RuntimeEngineCommandOutput::new(
            0,
            format!("sha256:{}|linux/arm64\n", "6".repeat(64)).into_bytes(),
        )],
    );
    fetcher
        .fetch(
            &oci_candidate(CpuArchitecture::Arm64),
            Path::new("/runtime"),
            &destination,
        )
        .expect("acquire");
    let receipt = fs::read_to_string(destination.join("li_engine_oci_v1.json")).expect("receipt");
    assert!(receipt.contains("\"name\":\"li_engine_oci_receipt\""));
    assert!(receipt.contains("\"platform\":\"linux/arm64\""));
    let commands = runner.commands.lock().expect("commands");
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].arguments()[..2], ["image", "inspect"]);
}

// Pulls one missing x86 image with Docker spelling and then re-inspects exact identity.
#[test]
fn missing_image_pulls_exact_reference_and_reverifies() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, runner, _) = fetcher(
        &directory,
        vec![
            RuntimeEngineCommandOutput::new(1, Vec::new()),
            RuntimeEngineCommandOutput::new(0, Vec::new()),
            RuntimeEngineCommandOutput::new(
                0,
                format!("sha256:{}|linux/amd64\n", "6".repeat(64)).into_bytes(),
            ),
        ],
    );
    fetcher
        .fetch(
            &oci_candidate(CpuArchitecture::X86_64),
            Path::new("/runtime"),
            &destination,
        )
        .expect("acquire");
    let commands = runner.commands.lock().expect("commands");
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[1].arguments()[0], "pull");
    assert_eq!(commands[1].arguments()[2], "linux/amd64");
    assert!(commands[1].arguments()[3].contains("@sha256:"));
}

// Preserves an exact preexisting configuration and both preexisting tags through cleanup.
#[test]
fn prepared_engine_preserves_preexisting_config_and_tags() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let reference = candidate_engine_reference();
    let local_tag = "li-verifier/candidate:fixture";
    let (fetcher, runner) =
        ownership_fetcher(&directory, true, &[&reference, local_tag], false, false);
    let (artifacts, cleanup) = exact_ownership_inputs(&directory);
    let ownership = acquire_exact(&fetcher, &artifacts, &cleanup, &destination);
    assert!(ownership.preexisting_config());
    assert!(ownership.preexisting_reference());
    assert!(ownership.preexisting_local_tag());
    assert!(!ownership.created_config());
    fetcher
        .remove_exact(&ownership)
        .expect("preserve exact image");
    let state = runner.state.lock().expect("state");
    assert!(state.config_present);
    assert_eq!(state.tags.len(), 2);
    assert!(runner
        .commands
        .lock()
        .expect("commands")
        .iter()
        .all(|command| {
            !matches!(
                command.arguments().first().map(String::as_str),
                Some("load") | Some("tag")
            ) && command.arguments().get(1).map(String::as_str) != Some("rm")
        }));
}

// Skips load and tag when the exact configuration preexists without either candidate tag.
#[test]
fn prepared_engine_skips_preexisting_untagged_config() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, runner) = ownership_fetcher(&directory, true, &[], false, false);
    let (artifacts, cleanup) = exact_ownership_inputs(&directory);
    let ownership = acquire_exact(&fetcher, &artifacts, &cleanup, &destination);
    assert!(ownership.preexisting_config());
    assert!(!ownership.preexisting_reference());
    assert!(!ownership.preexisting_local_tag());
    fetcher
        .remove_exact(&ownership)
        .expect("preserve untagged config");
    let state = runner.state.lock().expect("state");
    assert!(state.config_present);
    assert!(state.tags.is_empty());
    assert!(runner
        .commands
        .lock()
        .expect("commands")
        .iter()
        .all(|command| {
            !matches!(
                command.arguments().first().map(String::as_str),
                Some("load") | Some("tag")
            )
        }));
}

// Removes only newly loaded config/tags and replays acquisition and cleanup idempotently.
#[test]
fn newly_loaded_engine_cleanup_is_exact_restart_safe_and_idempotent() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, runner) = ownership_fetcher(&directory, false, &[], false, false);
    let (artifacts, cleanup) = exact_ownership_inputs(&directory);
    let ownership = acquire_exact(&fetcher, &artifacts, &cleanup, &destination);
    assert!(ownership.created_config());
    assert!(ownership.created_reference());
    assert!(ownership.created_local_tag());

    let replay_destination = directory.path().join("replay-engine");
    fs::create_dir(&replay_destination).expect("replay destination");
    #[cfg(unix)]
    fs::set_permissions(
        &replay_destination,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private replay destination");
    let replay = fetcher
        .fetch_exact(
            &oci_candidate(CpuArchitecture::Arm64),
            &artifacts,
            Some(&ownership),
            Path::new("/runtime"),
            &replay_destination,
        )
        .expect("restart acquisition")
        .expect("restart ownership");
    assert_eq!(replay, ownership);
    fetcher.remove_exact(&ownership).expect("remove exact");
    fetcher
        .remove_exact(&ownership)
        .expect("idempotent cleanup");
    let state = runner.state.lock().expect("state");
    assert!(!state.config_present);
    assert!(state.tags.is_empty());
    assert!(runner
        .commands
        .lock()
        .expect("commands")
        .iter()
        .all(|command| {
            command.arguments().first().map(String::as_str) != Some("system")
                && !command
                    .arguments()
                    .iter()
                    .any(|argument| argument == "prune")
        }));
}

// Recovers ambiguous load and tag responses only after exact state reread proves success.
#[test]
fn exact_engine_response_loss_is_resolved_by_identity_reread() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, _) = ownership_fetcher(&directory, false, &[], true, true);
    let (artifacts, cleanup) = exact_ownership_inputs(&directory);
    let ownership = acquire_exact(&fetcher, &artifacts, &cleanup, &destination);
    assert!(ownership.created_config());
    assert!(ownership.created_reference());
    assert!(ownership.created_local_tag());
}

// Retains every image identity when a transaction-owned tag is rebound concurrently.
#[test]
fn concurrent_exact_tag_drift_retains_image_and_recovery_marker() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, runner) = ownership_fetcher(&directory, false, &[], false, false);
    let (artifacts, cleanup) = exact_ownership_inputs(&directory);
    let ownership = acquire_exact(&fetcher, &artifacts, &cleanup, &destination);
    runner.drift_tag(cleanup.reference());
    assert_eq!(
        fetcher.remove_exact(&ownership),
        Err(RuntimeError::EngineAcquisitionInvalid)
    );
    let state = runner.state.lock().expect("state");
    assert!(state.config_present);
    assert!(state.tags.contains_key(cleanup.reference()));
    assert!(state.tags.contains_key(cleanup.local_tag()));
}

// Cleans a prepared no-mutation marker but retains it when local state changed after observation.
#[test]
fn prepared_exact_cleanup_requires_unchanged_observation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (fetcher, runner) = ownership_fetcher(&directory, false, &[], false, false);
    let (_, cleanup) = exact_ownership_inputs(&directory);
    let prepared = fetcher.prepare_exact(&cleanup).expect("prepared");
    fetcher
        .remove_exact(&prepared)
        .expect("unchanged prepared cleanup");
    runner.state.lock().expect("state").config_present = true;
    assert_eq!(
        fetcher.remove_exact(&prepared),
        Err(RuntimeError::EngineAcquisitionInvalid)
    );
}

// Rejects mismatched identity, platform, malformed inspection, and pull failure transactionally.
#[test]
fn docker_result_mutation_matrix_fails_closed() {
    let mutations = vec![
        vec![RuntimeEngineCommandOutput::new(
            0,
            format!("sha256:{}|linux/arm64", "f".repeat(64)).into_bytes(),
        )],
        vec![RuntimeEngineCommandOutput::new(
            0,
            format!("sha256:{}|linux/amd64", "6".repeat(64)).into_bytes(),
        )],
        vec![RuntimeEngineCommandOutput::new(0, b"malformed".to_vec())],
        vec![
            RuntimeEngineCommandOutput::new(1, Vec::new()),
            RuntimeEngineCommandOutput::new(1, Vec::new()),
        ],
        vec![
            RuntimeEngineCommandOutput::new(1, Vec::new()),
            RuntimeEngineCommandOutput::new(0, Vec::new()),
            RuntimeEngineCommandOutput::new(1, Vec::new()),
        ],
    ];
    for (index, outputs) in mutations.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = destination(&directory);
        let (fetcher, _, io) = fetcher(&directory, outputs);
        assert!(
            fetcher
                .fetch(
                    &oci_candidate(CpuArchitecture::Arm64),
                    Path::new("/runtime"),
                    &destination,
                )
                .is_err(),
            "mutation={index}"
        );
        assert!(destination
            .read_dir()
            .expect("destination")
            .next()
            .is_none());
        assert_eq!(io.clears.load(Ordering::SeqCst), 1);
    }
}

// Propagates process-provider failure without producing a receipt.
#[test]
fn injected_runner_failure_is_stable_and_transactional() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let runner = Arc::new(MockRunner {
        outputs: Mutex::new(VecDeque::from([Err(
            RuntimeError::EngineAcquisitionUnavailable,
        )])),
        commands: Mutex::new(Vec::new()),
    });
    let io = Arc::new(FailingIo::new());
    let fetcher = DockerRuntimeEngineFetcher::new(
        PathBuf::from("/usr/bin/docker"),
        directory.path().to_path_buf(),
        Vec::new(),
        runner,
        io.clone(),
    )
    .expect("fetcher");
    assert_eq!(
        fetcher
            .fetch(
                &oci_candidate(CpuArchitecture::Arm64),
                Path::new("/runtime"),
                &destination,
            )
            .expect_err("runner"),
        RuntimeError::EngineAcquisitionUnavailable
    );
    assert_eq!(io.clears.load(Ordering::SeqCst), 1);
}

// Rejects native distributions without falling back to Docker or another Engine identity.
#[test]
fn native_distribution_is_not_silently_treated_as_oci() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let (fetcher, runner, io) = fetcher(&directory, Vec::new());
    assert_eq!(
        fetcher
            .fetch(&native_candidate(), Path::new("/runtime"), &destination,)
            .expect_err("native"),
        RuntimeError::EngineAcquisitionInvalid
    );
    assert!(runner.commands.lock().expect("commands").is_empty());
    assert_eq!(io.clears.load(Ordering::SeqCst), 0);
}

// Exercises failure at every injected Engine receipt I/O boundary.
#[test]
fn engine_io_failure_matrix_covers_prepare_receipt_and_cleanup() {
    for step in ["prepare", "receipt"] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = destination(&directory);
        let (fetcher, _, io) = fetcher(
            &directory,
            vec![RuntimeEngineCommandOutput::new(
                0,
                format!("sha256:{}|linux/arm64", "6".repeat(64)).into_bytes(),
            )],
        );
        *io.step.lock().expect("step") = Some(step);
        assert!(
            fetcher
                .fetch(
                    &oci_candidate(CpuArchitecture::Arm64),
                    Path::new("/runtime"),
                    &destination,
                )
                .is_err(),
            "step={step}"
        );
        if step == "receipt" {
            assert_eq!(io.clears.load(Ordering::SeqCst), 1);
        }
    }
}

// Rejects unsafe executable, working directory, duplicate environment, and secret names.
#[test]
fn provider_composition_rejects_every_unsafe_native_input() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let runner = Arc::new(MockRunner::new(Vec::new()));
    let io = Arc::new(FailingIo::new());
    assert!(DockerRuntimeEngineFetcher::new(
        PathBuf::from("docker"),
        directory.path().to_path_buf(),
        Vec::new(),
        runner.clone(),
        io.clone(),
    )
    .is_err());
    assert!(DockerRuntimeEngineFetcher::new(
        PathBuf::from("/usr/bin/docker"),
        PathBuf::from("relative"),
        Vec::new(),
        runner.clone(),
        io.clone(),
    )
    .is_err());
    for environment in [
        vec![
            ("HOME".to_string(), "/a".to_string()),
            ("HOME".to_string(), "/b".to_string()),
        ],
        vec![("DOCKER_AUTH_CONFIG".to_string(), "value".to_string())],
        vec![("lowercase".to_string(), "value".to_string())],
    ] {
        assert!(DockerRuntimeEngineFetcher::new(
            PathBuf::from("/usr/bin/docker"),
            directory.path().to_path_buf(),
            environment,
            runner.clone(),
            io.clone(),
        )
        .is_err());
    }
}

// Executes one benign command through the real shell-free process runner.
#[test]
fn system_engine_command_runner_executes_exact_argv_and_bounds_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let command = RuntimeEngineCommand::new(
        PathBuf::from("/usr/bin/printf"),
        vec!["ready".to_string()],
        Vec::new(),
        directory.path().to_path_buf(),
    )
    .expect("command");
    let runner = SystemRuntimeEngineCommandRunner;
    assert_eq!(
        runner.run(&command, 5).expect("run"),
        RuntimeEngineCommandOutput::new(0, b"ready".to_vec())
    );
    assert_eq!(
        runner.run(&command, 4).expect_err("bound"),
        RuntimeError::EngineAcquisitionInvalid
    );
}

// Enforces private atomic receipt activation and refuses overwrite or symlink state.
#[test]
fn system_engine_io_enforces_private_no_follow_contract() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let destination = destination(&directory);
    let io = SystemDockerRuntimeEngineIo;
    io.prepare_destination(&destination).expect("prepare");
    io.write_receipt(&destination, b"{}\n").expect("receipt");
    assert!(io.write_receipt(&destination, b"{}\n").is_err());
    io.clear_destination(&destination).expect("clear");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("foreign", destination.join("link")).expect("symlink");
        assert!(io.clear_destination(&destination).is_err());
        fs::remove_file(destination.join("link")).expect("remove link");
    }
}
