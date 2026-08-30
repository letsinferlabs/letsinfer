// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    ArtifactRevision, LogicalModelName, RuntimeInstallationId, RuntimeVersion, Sha256Digest,
    TaskId, TechnicalName,
};
use li_runtime_manager::{
    RuntimeCandidate, RuntimeCatalogProvider, RuntimeEmbeddedApplicationAcquisition,
    RuntimeEmbeddedApplicationAcquisitionRequest, RuntimeEmbeddedApplicationExecution,
    RuntimeEmbeddedApplicationExecutionRequest, RuntimeEmbeddedApplicationProvider, RuntimeError,
    RuntimeExecutionContainer, RuntimeExecutionDistribution, RuntimeExecutionManifest,
    RuntimeExecutionManifestProvider, RuntimeExecutionPlatform, RuntimeExecutionReadiness,
    RuntimeExecutionServing, RuntimeExecutionTask, RuntimeManager, RuntimeTaskLauncher,
};

// Returns one exact embedded execution manifest for the manager handoff boundary.
fn manifest() -> RuntimeExecutionManifest {
    let task_id = TaskId::parse("task-0").expect("task");
    RuntimeExecutionManifest::new(
        RuntimeInstallationId::parse(&"1".repeat(32)).expect("installation"),
        LogicalModelName::parse("fixture-model").expect("model"),
        RuntimeExecutionPlatform::MacosArm64,
        TechnicalName::parse("fixture").expect("engine"),
        RuntimeExecutionDistribution::EmbeddedApplication {
            bundle_id: "ai.letsinfer.fixture".to_string(),
            embedded_engine: "fixture".to_string(),
            payload_id: Sha256Digest::parse(&"6".repeat(64)).expect("payload"),
            source_revision: ArtifactRevision::parse(&"7".repeat(40)).expect("revision"),
            minimum_version: RuntimeVersion::parse("1.0.0").expect("version"),
            entrypoint: PathBuf::from("adapter/engine-adapter"),
            port_count: 1,
        },
        Vec::new(),
        Vec::new(),
        "native".to_string(),
        false,
        RuntimeExecutionContainer::new(1024, 0, Duration::from_secs(30), None).expect("container"),
        RuntimeExecutionServing::new(4, 2, 4096, "/v1/letsinfer/token-count".to_string())
            .expect("serving"),
        PathBuf::from("/runtime"),
        PathBuf::from("/models"),
        PathBuf::from("/engine"),
        PathBuf::from("/cache"),
        vec![RuntimeExecutionTask::new(
            task_id.clone(),
            RuntimeTaskLauncher::Manifest,
            Vec::new(),
            1,
            1,
            true,
            RuntimeExecutionReadiness::Manifest,
        )
        .expect("task")],
        vec![vec![task_id]],
    )
    .expect("manifest")
}

// Supplies one already-verified execution manifest and binds the requested identity.
struct MockManifests {
    value: RuntimeExecutionManifest,
}

impl RuntimeExecutionManifestProvider for MockManifests {
    // Returns the configured manifest only for its exact installation identity.
    fn manifest(
        &self,
        installation_id: &RuntimeInstallationId,
    ) -> Result<RuntimeExecutionManifest, RuntimeError> {
        if installation_id != self.value.installation_id() {
            return Err(RuntimeError::InstallationNotFound);
        }
        Ok(self.value.clone())
    }
}

// Supplies no catalog values because the handoff never performs selection.
struct EmptyCatalog;

impl RuntimeCatalogProvider for EmptyCatalog {
    // Returns no candidates for the execution-only manager fixture.
    fn candidates(&self, _model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        Ok(Vec::new())
    }
}

// Mocks only the independently supervised execution capability under test.
struct MockApplication {
    calls: AtomicUsize,
    failure: Option<RuntimeError>,
    mismatch: Option<&'static str>,
    application_version: RuntimeVersion,
    application_handle: String,
    observed: Mutex<Option<RuntimeEmbeddedApplicationExecutionRequest>>,
}

impl MockApplication {
    // Creates one deterministic application execution result.
    fn new(failure: Option<RuntimeError>, mismatch: Option<&'static str>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            failure,
            mismatch,
            application_version: RuntimeVersion::parse("1.0.0").expect("version"),
            application_handle: "app-owned-fixture-handle".to_string(),
            observed: Mutex::new(None),
        }
    }

    // Creates one application response with an explicit version and opaque handle.
    fn responding_with(version: &str, application_handle: String) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            failure: None,
            mismatch: None,
            application_version: RuntimeVersion::parse(version).expect("version"),
            application_handle,
            observed: Mutex::new(None),
        }
    }
}

impl RuntimeEmbeddedApplicationProvider for MockApplication {
    // Acquisition is outside this execution-focused provider matrix.
    fn acquire(
        &self,
        _request: &RuntimeEmbeddedApplicationAcquisitionRequest,
    ) -> Result<RuntimeEmbeddedApplicationAcquisition, RuntimeError> {
        Err(RuntimeError::EmbeddedApplicationUnavailable)
    }

    // Returns an exact or deliberately mismatched handoff receipt.
    fn execute(
        &self,
        request: &RuntimeEmbeddedApplicationExecutionRequest,
    ) -> Result<RuntimeEmbeddedApplicationExecution, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.observed.lock().expect("observed") = Some(request.clone());
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        RuntimeEmbeddedApplicationExecution::new(
            if self.mismatch == Some("installation") {
                RuntimeInstallationId::parse(&"2".repeat(32)).expect("mismatch")
            } else {
                request.installation_id().clone()
            },
            if self.mismatch == Some("bundle") {
                "ai.letsinfer.foreign".to_string()
            } else {
                request.bundle_id().to_string()
            },
            TechnicalName::parse(if self.mismatch == Some("engine") {
                "foreign"
            } else {
                request.embedded_engine().as_str()
            })
            .expect("engine"),
            if self.mismatch == Some("payload") {
                Sha256Digest::parse(&"f".repeat(64)).expect("payload")
            } else {
                request.payload_id().clone()
            },
            self.application_version.clone(),
            self.application_handle.clone(),
        )
    }
}

// Transfers one exact verified manifest and returns only the app-owned opaque handle.
#[test]
fn embedded_execution_handoff_preserves_the_complete_identity() {
    let manifest = manifest();
    let application = Arc::new(MockApplication::new(None, None));
    let manager = RuntimeManager::new(Arc::new(EmptyCatalog))
        .with_execution_provider(Arc::new(MockManifests {
            value: manifest.clone(),
        }))
        .with_embedded_application_provider(application.clone());
    let execution = manager
        .execute_embedded_application(manifest.installation_id())
        .expect("execution handoff");
    assert_eq!(execution.installation_id(), manifest.installation_id());
    assert_eq!(execution.application_version().as_str(), "1.0.0");
    assert_eq!(execution.application_handle(), "app-owned-fixture-handle");
    assert_eq!(application.calls.load(Ordering::SeqCst), 1);
    let request = application
        .observed
        .lock()
        .expect("observed")
        .clone()
        .expect("request");
    assert_eq!(request.logical_model().as_str(), "fixture-model");
    assert_eq!(request.bundle_id(), "ai.letsinfer.fixture");
    assert_eq!(request.embedded_engine().as_str(), "fixture");
    assert_eq!(request.payload_id().as_str(), "6".repeat(64));
    assert_eq!(request.source_revision().as_str(), "7".repeat(40));
    assert_eq!(request.minimum_version().as_str(), "1.0.0");
    assert_eq!(
        request.entrypoint(),
        PathBuf::from("adapter/engine-adapter")
    );
    assert_eq!(request.port_count(), 1);
}

// Fails closed for an absent app, provider failure, and every altered result identity.
#[test]
fn embedded_execution_handoff_failure_matrix_has_no_fallback() {
    let manifest = manifest();
    let manager = RuntimeManager::new(Arc::new(EmptyCatalog)).with_execution_provider(Arc::new(
        MockManifests {
            value: manifest.clone(),
        },
    ));
    assert_eq!(
        manager
            .execute_embedded_application(manifest.installation_id())
            .expect_err("provider required"),
        RuntimeError::EmbeddedApplicationUnavailable
    );

    for (failure, mismatch, expected) in [
        (
            Some(RuntimeError::EmbeddedApplicationUnavailable),
            None,
            RuntimeError::EmbeddedApplicationUnavailable,
        ),
        (
            None,
            Some("installation"),
            RuntimeError::EmbeddedApplicationInvalid,
        ),
        (
            None,
            Some("bundle"),
            RuntimeError::EmbeddedApplicationInvalid,
        ),
        (
            None,
            Some("engine"),
            RuntimeError::EmbeddedApplicationInvalid,
        ),
        (
            None,
            Some("payload"),
            RuntimeError::EmbeddedApplicationInvalid,
        ),
    ] {
        let manager = RuntimeManager::new(Arc::new(EmptyCatalog))
            .with_execution_provider(Arc::new(MockManifests {
                value: manifest.clone(),
            }))
            .with_embedded_application_provider(Arc::new(MockApplication::new(failure, mismatch)));
        assert_eq!(
            manager
                .execute_embedded_application(manifest.installation_id())
                .expect_err("handoff failure"),
            expected
        );
    }
}

// Enforces semantic application-version precedence at the execution boundary.
#[test]
fn embedded_execution_handoff_rejects_every_application_version_below_the_minimum() {
    let manifest = manifest();
    for (version, accepted) in [
        ("0.9.9", false),
        ("1.0.0-rc.1", false),
        ("1.0.0", true),
        ("1.0.1-rc.1", true),
        ("1.1.0", true),
    ] {
        let manager = RuntimeManager::new(Arc::new(EmptyCatalog))
            .with_execution_provider(Arc::new(MockManifests {
                value: manifest.clone(),
            }))
            .with_embedded_application_provider(Arc::new(MockApplication::responding_with(
                version,
                "handle".to_string(),
            )));
        let result = manager.execute_embedded_application(manifest.installation_id());
        assert_eq!(result.is_ok(), accepted, "application_version={version}");
    }
}

// Rejects malformed app-owned handles before they can escape the typed boundary.
#[test]
fn embedded_execution_handoff_rejects_malformed_application_handles() {
    let manifest = manifest();
    for handle in [String::new(), "line\nbreak".to_string(), "x".repeat(513)] {
        let manager = RuntimeManager::new(Arc::new(EmptyCatalog))
            .with_execution_provider(Arc::new(MockManifests {
                value: manifest.clone(),
            }))
            .with_embedded_application_provider(Arc::new(MockApplication::responding_with(
                "1.0.0", handle,
            )));
        assert_eq!(
            manager
                .execute_embedded_application(manifest.installation_id())
                .expect_err("invalid handle"),
            RuntimeError::EmbeddedApplicationInvalid
        );
    }
}
