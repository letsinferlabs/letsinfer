// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;

use li_runtime_manager::{
    ComposedRuntimeArtifactFetcher, ComposedRuntimeEngineFetcher, CurlRuntimeHttpClient,
    DockerRuntimeEngineFetcher, Ed25519RuntimeCatalogSignatureVerifier,
    FilesystemRuntimeArtifactProvider, FilesystemRuntimeArtifactVerifier,
    FilesystemRuntimeCatalogCache, FilesystemRuntimeCatalogHydrationWorkspace,
    FilesystemRuntimeExecutionManifestProvider, HuggingFaceRuntimeModelFetcher,
    NativeRuntimeEngineFetcher, OciRuntimeCatalogCandidateHydrator, OciRuntimePackFetcher,
    RandomRuntimeHttpIdentityProvider, RuntimeError, RuntimeExecutionManifestProvider,
    RuntimeHttpClient, RuntimeInstallationStore, RuntimeManager, SignedRuntimeCatalogProvider,
    StaticRuntimeCatalogTrustProvider, StoredRuntimeInstallationProvider,
    SystemDockerRuntimeEngineIo, SystemNativeRuntimeEngineIo, SystemRuntimeArtifactClosureIo,
    SystemRuntimeCatalogClock, SystemRuntimeClock, SystemRuntimeEngineCommandRunner,
    SystemRuntimeExecutionManifestIo, SystemRuntimeHttpCommandRunner, SystemRuntimeHttpWorkspaceIo,
    SystemRuntimeInstallationIdentityProvider, SystemRuntimeModelArtifactIo,
    SystemRuntimePackArtifactIo,
};

// Carries every explicit native and managed path required by production RuntimeManager composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreModelRuntimeCompositionInput {
    pub catalog_source: String,
    pub catalog_cache_root: PathBuf,
    pub catalog_hydration_root: PathBuf,
    pub http_workspace_root: PathBuf,
    pub installation_root: PathBuf,
    pub runtime_cache_root: PathBuf,
    pub curl_command: PathBuf,
    pub docker_command: PathBuf,
    pub command_working_directory: PathBuf,
}

// Retains one manager and the verified execution surface consumed by placement composition.
pub struct CoreModelRuntimeComposition {
    manager: Arc<RuntimeManager>,
    catalog: Arc<SignedRuntimeCatalogProvider>,
    executions: Arc<dyn RuntimeExecutionManifestProvider>,
    http: Arc<dyn RuntimeHttpClient>,
}

impl CoreModelRuntimeComposition {
    // Returns the complete production RuntimeManager without exposing its provider graph.
    pub fn manager(&self) -> Arc<RuntimeManager> {
        self.manager.clone()
    }

    // Returns the same verified signed catalog provider consumed by RuntimeManager.
    pub fn catalog(&self) -> Arc<SignedRuntimeCatalogProvider> {
        self.catalog.clone()
    }

    // Returns the same verified execution provider owned by RuntimeManager.
    pub fn executions(&self) -> Arc<dyn RuntimeExecutionManifestProvider> {
        self.executions.clone()
    }

    // Returns the same credential-free bounded HTTP client used by immutable runtime acquisition.
    pub fn http(&self) -> Arc<dyn RuntimeHttpClient> {
        self.http.clone()
    }
}

// Composes signed selection, immutable acquisition, persistence, and execution verification.
pub fn compose_core_model_runtime(
    input: CoreModelRuntimeCompositionInput,
    store: Arc<dyn RuntimeInstallationStore>,
) -> Result<CoreModelRuntimeComposition, RuntimeError> {
    let http: Arc<dyn RuntimeHttpClient> = Arc::new(CurlRuntimeHttpClient::new(
        input.curl_command,
        input.http_workspace_root,
        Arc::new(SystemRuntimeHttpCommandRunner),
        Arc::new(RandomRuntimeHttpIdentityProvider),
        Arc::new(SystemRuntimeHttpWorkspaceIo),
    )?);
    let pack_io = Arc::new(SystemRuntimePackArtifactIo);
    let packs = Arc::new(OciRuntimePackFetcher::new(http.clone(), pack_io.clone()));
    let workspaces = Arc::new(FilesystemRuntimeCatalogHydrationWorkspace::new(
        input.catalog_hydration_root,
    )?);
    let catalog = Arc::new(SignedRuntimeCatalogProvider::ordinary(
        input.catalog_source,
        http.clone(),
        Arc::new(Ed25519RuntimeCatalogSignatureVerifier),
        Arc::new(StaticRuntimeCatalogTrustProvider::letsinfer()?),
        Arc::new(FilesystemRuntimeCatalogCache::new(
            input.catalog_cache_root,
        )?),
        Arc::new(OciRuntimeCatalogCandidateHydrator::new(
            packs.clone(),
            workspaces,
        )),
        Arc::new(SystemRuntimeCatalogClock),
    )?);
    let model_fetcher = Arc::new(HuggingFaceRuntimeModelFetcher::new(
        http.clone(),
        Arc::new(SystemRuntimeModelArtifactIo),
    ));
    let native_io = Arc::new(SystemNativeRuntimeEngineIo);
    let docker_fetcher = Arc::new(DockerRuntimeEngineFetcher::new(
        input.docker_command,
        input.command_working_directory,
        Vec::new(),
        Arc::new(SystemRuntimeEngineCommandRunner),
        Arc::new(SystemDockerRuntimeEngineIo),
    )?);
    let native_fetcher = Arc::new(NativeRuntimeEngineFetcher::new(
        http.clone(),
        Arc::new(SystemRuntimeEngineCommandRunner),
        native_io.clone(),
    ));
    let fetcher = Arc::new(ComposedRuntimeArtifactFetcher::new(
        packs,
        model_fetcher,
        Arc::new(ComposedRuntimeEngineFetcher::new(
            docker_fetcher,
            native_fetcher,
        )),
    ));
    let verifier = Arc::new(FilesystemRuntimeArtifactVerifier::new(
        pack_io,
        native_io,
        Arc::new(SystemRuntimeArtifactClosureIo),
    ));
    let artifacts = Arc::new(FilesystemRuntimeArtifactProvider::new(
        input.installation_root.clone(),
        fetcher,
        verifier,
    )?);
    let installations = Arc::new(StoredRuntimeInstallationProvider::new(store.clone()));
    let executions: Arc<dyn RuntimeExecutionManifestProvider> =
        Arc::new(FilesystemRuntimeExecutionManifestProvider::new(
            input.installation_root,
            input.runtime_cache_root,
            installations,
            Arc::new(SystemRuntimeExecutionManifestIo),
        )?);
    let manager = RuntimeManager::with_lifecycle(
        catalog.clone(),
        artifacts,
        store,
        Arc::new(SystemRuntimeInstallationIdentityProvider),
        Arc::new(SystemRuntimeClock),
    )
    .with_execution_provider(executions.clone());
    Ok(CoreModelRuntimeComposition {
        manager: Arc::new(manager),
        catalog,
        executions,
        http,
    })
}
