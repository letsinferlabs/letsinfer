// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use li_core_interface::Sha256Digest;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const LETSINFER_PUBLIC_INFERENCE_TARGET: &str = "http://127.0.0.1:8000";
pub const LETSINFER_PUBLIC_HTTPS_PORT: u16 = 443;

const TAILSCALE_PROVIDER: &str = "tailscale-funnel";
const MAXIMUM_PROVIDER_OUTPUT_BYTES: usize = 1024 * 1024;
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);
const PROVIDER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROVIDER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

// Names one stable public-exposure provider failure without command or configuration detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayExposureError {
    InvalidConfiguration,
    GatewayUnavailable,
    AlreadyEnabled,
    NotEnabled,
    StateUnavailable,
    ProviderUnavailable,
    ProviderStateUnsafe,
    ProviderIdentityChanged,
    RollbackIncomplete,
}

impl fmt::Display for GatewayExposureError {
    // Presents fixed user-safe exposure failure language.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("Gateway exposure configuration is invalid")
            }
            Self::GatewayUnavailable => {
                formatter.write_str("The main-node Gateway is not ready for public exposure")
            }
            Self::AlreadyEnabled => formatter.write_str("Public inference is already enabled"),
            Self::NotEnabled => formatter.write_str("Public inference is not enabled"),
            Self::StateUnavailable => formatter.write_str("Gateway exposure state is unavailable"),
            Self::ProviderUnavailable => {
                formatter.write_str("Gateway exposure provider is unavailable")
            }
            Self::ProviderStateUnsafe => {
                formatter.write_str("Gateway exposure provider state is not exclusively owned")
            }
            Self::ProviderIdentityChanged => {
                formatter.write_str("Gateway exposure provider identity changed")
            }
            Self::RollbackIncomplete => {
                formatter.write_str("Gateway exposure rollback is incomplete")
            }
        }
    }
}

impl Error for GatewayExposureError {}

// Carries one exact verified public inference exposure without provider-private state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayExposure {
    public_url: String,
    configuration_sha256: Sha256Digest,
}

impl GatewayExposure {
    // Creates one persisted provider identity only from a canonical public HTTPS origin.
    pub fn new(
        public_url: String,
        configuration_sha256: Sha256Digest,
    ) -> Result<Self, GatewayExposureError> {
        let Some(host) = public_url.strip_prefix("https://") else {
            return Err(GatewayExposureError::InvalidConfiguration);
        };
        if host.is_empty()
            || host.contains('/')
            || host.ends_with('.')
            || !valid_dns_name(&format!("{host}."))
        {
            return Err(GatewayExposureError::InvalidConfiguration);
        }
        Ok(Self {
            public_url,
            configuration_sha256,
        })
    }

    // Returns the only supported public-exposure provider identity.
    pub const fn provider(&self) -> &'static str {
        TAILSCALE_PROVIDER
    }

    // Returns the verified public HTTPS origin without a trailing slash.
    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    // Returns the fixed local public Gateway target.
    pub const fn inference_target(&self) -> &'static str {
        LETSINFER_PUBLIC_INFERENCE_TARGET
    }

    // Returns the canonical provider configuration identity required for reset.
    pub const fn configuration_sha256(&self) -> &Sha256Digest {
        &self.configuration_sha256
    }
}

// Reports durable exposure state together with its current live verification result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayExposureStatus {
    exposure: Option<GatewayExposure>,
    provider_verified: bool,
}

impl GatewayExposureStatus {
    // Creates one coherent status from durable state and its live verification judgment.
    pub fn new(
        exposure: Option<GatewayExposure>,
        provider_verified: bool,
    ) -> Result<Self, GatewayExposureError> {
        if exposure.is_none() && !provider_verified {
            return Err(GatewayExposureError::InvalidConfiguration);
        }
        Ok(Self {
            exposure,
            provider_verified,
        })
    }

    // Returns the durable enabled exposure, or none when public inference is disabled.
    pub const fn exposure(&self) -> Option<&GatewayExposure> {
        self.exposure.as_ref()
    }

    // Returns whether live provider state agrees with the complete durable identity.
    pub const fn provider_verified(&self) -> bool {
        self.provider_verified
    }
}

// Persists only the exact exposure identity owned by GatewayManager.
pub trait GatewayExposureStore: Send + Sync {
    // Reads the durable enabled exposure, or none when exposure is disabled.
    fn exposure(&self) -> Result<Option<GatewayExposure>, GatewayExposureError>;

    // Atomically replaces one exact observed state with the complete replacement state.
    fn replace(
        &self,
        expected: Option<&GatewayExposure>,
        replacement: Option<&GatewayExposure>,
    ) -> Result<(), GatewayExposureError>;
}

// Proves that the local main-node Gateway is active and healthy before public mutation.
pub trait GatewayExposureReadinessProvider: Send + Sync {
    // Requires the exact public Gateway configuration and live health contract.
    fn require_ready(&self) -> Result<(), GatewayExposureError>;
}

// Owns one external public-exposure mechanism beneath Gateway policy.
pub trait GatewayExposureProvider: Send + Sync {
    // Enables one exact inference-only public exposure.
    fn enable(&self) -> Result<GatewayExposure, GatewayExposureError>;

    // Verifies live provider state against one exact committed identity.
    fn verify(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposure, GatewayExposureError>;

    // Disables only one exact committed provider identity.
    fn disable(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<(), GatewayExposureError>;
}

// Owns durable public-exposure state, readiness, verification, and compensation.
pub struct GatewayExposureCoordinator {
    store: Arc<dyn GatewayExposureStore>,
    readiness: Arc<dyn GatewayExposureReadinessProvider>,
    provider: Arc<dyn GatewayExposureProvider>,
}

impl GatewayExposureCoordinator {
    // Creates one exposure owner from explicit persistence and native capabilities.
    pub const fn new(
        store: Arc<dyn GatewayExposureStore>,
        readiness: Arc<dyn GatewayExposureReadinessProvider>,
        provider: Arc<dyn GatewayExposureProvider>,
    ) -> Self {
        Self {
            store,
            readiness,
            provider,
        }
    }

    // Reads durable state and verifies every enabled identity against the live provider.
    pub fn status(&self) -> Result<GatewayExposureStatus, GatewayExposureError> {
        let exposure = self.store.exposure()?;
        let provider_verified = match exposure.as_ref() {
            None => true,
            Some(expected) => self
                .provider
                .verify(expected.configuration_sha256())
                .is_ok_and(|observed| observed == *expected),
        };
        GatewayExposureStatus::new(exposure, provider_verified)
    }

    // Enables public inference only after readiness and compensates a failed state commit.
    pub fn enable(&self) -> Result<GatewayExposure, GatewayExposureError> {
        self.readiness.require_ready()?;
        if self.store.exposure()?.is_some() {
            return Err(GatewayExposureError::AlreadyEnabled);
        }
        let exposure = self.provider.enable()?;
        if let Err(error) = self.store.replace(None, Some(&exposure)) {
            if self
                .provider
                .disable(exposure.configuration_sha256())
                .is_err()
            {
                return Err(GatewayExposureError::RollbackIncomplete);
            }
            return Err(error);
        }
        Ok(exposure)
    }

    // Disables only the committed identity and restores it if state commit fails.
    pub fn disable(&self) -> Result<(), GatewayExposureError> {
        let exposure = self
            .store
            .exposure()?
            .ok_or(GatewayExposureError::NotEnabled)?;
        self.disable_exposure(exposure)
    }

    // Disables one matching committed identity or accepts its exact absent-state replay.
    pub fn disable_matching(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<(), GatewayExposureError> {
        let Some(exposure) = self.store.exposure()? else {
            return Ok(());
        };
        if exposure.configuration_sha256() != expected_configuration_sha256 {
            return Err(GatewayExposureError::ProviderIdentityChanged);
        }
        self.disable_exposure(exposure)
    }

    // Applies one exact committed disable and restores the same identity if persistence fails.
    fn disable_exposure(&self, exposure: GatewayExposure) -> Result<(), GatewayExposureError> {
        self.provider.disable(exposure.configuration_sha256())?;
        if let Err(error) = self.store.replace(Some(&exposure), None) {
            let restored = self.provider.enable();
            if restored.as_ref() != Ok(&exposure) {
                return Err(GatewayExposureError::RollbackIncomplete);
            }
            return Err(error);
        }
        Ok(())
    }
}

// Describes one exact bounded provider process invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayExposureCommand {
    executable: PathBuf,
    arguments: Vec<OsString>,
    timeout: Duration,
    maximum_output_bytes: usize,
}

impl GatewayExposureCommand {
    // Creates one fixed Tailscale command from validated provider-owned arguments.
    fn new(executable: &Path, arguments: &[&str]) -> Self {
        Self {
            executable: executable.to_path_buf(),
            arguments: arguments.iter().map(OsString::from).collect(),
            timeout: PROVIDER_TIMEOUT,
            maximum_output_bytes: MAXIMUM_PROVIDER_OUTPUT_BYTES,
        }
    }

    // Returns the exact executable selected during provider composition.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns the complete shell-free argument vector.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    // Returns the complete process deadline.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    // Returns the aggregate retained output ceiling.
    pub const fn maximum_output_bytes(&self) -> usize {
        self.maximum_output_bytes
    }
}

// Carries bounded provider output used only by the exposure adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayExposureCommandOutput {
    status: i32,
    standard_output: Vec<u8>,
    standard_error: Vec<u8>,
    timed_out: bool,
}

impl GatewayExposureCommandOutput {
    // Creates one command result only when its combined output remains bounded.
    pub fn new(
        status: i32,
        standard_output: Vec<u8>,
        standard_error: Vec<u8>,
        timed_out: bool,
    ) -> Result<Self, GatewayExposureError> {
        if standard_output
            .len()
            .checked_add(standard_error.len())
            .is_none_or(|bytes| bytes > MAXIMUM_PROVIDER_OUTPUT_BYTES)
        {
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        Ok(Self {
            status,
            standard_output,
            standard_error,
            timed_out,
        })
    }

    // Returns whether the provider completed successfully before its deadline.
    pub const fn is_success(&self) -> bool {
        self.status == 0 && !self.timed_out
    }

    // Returns bounded standard output required for JSON parsing.
    pub fn standard_output(&self) -> &[u8] {
        &self.standard_output
    }

    // Returns bounded diagnostics retained only at the native command boundary.
    pub fn standard_error(&self) -> &[u8] {
        &self.standard_error
    }

    // Returns whether the native runner enforced the process deadline.
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }
}

// Executes exact public-exposure commands without a shell.
pub trait GatewayExposureCommandRunner: Send + Sync {
    // Runs one fixed command and returns only bounded output.
    fn run(
        &self,
        command: &GatewayExposureCommand,
    ) -> Result<GatewayExposureCommandOutput, GatewayExposureError>;
}

// Executes validated Tailscale commands on the active Unix host.
#[derive(Default)]
pub struct SystemGatewayExposureCommandRunner;

impl GatewayExposureCommandRunner for SystemGatewayExposureCommandRunner {
    // Spawns exact argv with no inherited environment and bounded timeout cleanup.
    fn run(
        &self,
        command: &GatewayExposureCommand,
    ) -> Result<GatewayExposureCommandOutput, GatewayExposureError> {
        require_trusted_tailscale(command.executable())?;
        let deadline = Instant::now()
            .checked_add(command.timeout())
            .ok_or(GatewayExposureError::ProviderUnavailable)?;
        let mut child = Command::new(command.executable())
            .args(command.arguments())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| GatewayExposureError::ProviderUnavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(GatewayExposureError::ProviderUnavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(GatewayExposureError::ProviderUnavailable)?;
        let maximum = command.maximum_output_bytes();
        let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, maximum));
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(-1),
                Ok(None) if Instant::now() < deadline => thread::sleep(PROVIDER_POLL_INTERVAL),
                Ok(None) => {
                    timed_out = true;
                    child
                        .kill()
                        .map_err(|_| GatewayExposureError::ProviderUnavailable)?;
                    break wait_for_exit(&mut child)?;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = wait_for_exit(&mut child);
                    return Err(GatewayExposureError::ProviderUnavailable);
                }
            }
        };
        let standard_output = join_output(stdout_reader)?;
        let standard_error = join_output(stderr_reader)?;
        if standard_output
            .len()
            .checked_add(standard_error.len())
            .is_none_or(|bytes| bytes > command.maximum_output_bytes())
        {
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        GatewayExposureCommandOutput::new(status, standard_output, standard_error, timed_out)
    }
}

// Owns the exact Tailscale Funnel mechanism beneath Gateway policy.
pub struct TailscaleGatewayExposureProvider {
    executable: PathBuf,
    runner: Arc<dyn GatewayExposureCommandRunner>,
}

// Discovers one exact trusted Tailscale installation only when an exposure action is requested.
pub struct SystemGatewayExposureProvider {
    runner: Arc<dyn GatewayExposureCommandRunner>,
}

impl SystemGatewayExposureProvider {
    // Creates the production lazy provider without making Tailscale a daemon-start dependency.
    pub fn new() -> Self {
        Self {
            runner: Arc::new(SystemGatewayExposureCommandRunner),
        }
    }

    // Selects the first ordinary non-link executable from the closed trusted path set.
    fn provider(&self) -> Result<TailscaleGatewayExposureProvider, GatewayExposureError> {
        for path in [
            PathBuf::from("/usr/bin/tailscale"),
            PathBuf::from("/usr/local/bin/tailscale"),
            PathBuf::from("/opt/homebrew/bin/tailscale"),
        ] {
            if require_trusted_tailscale(&path).is_ok() {
                return TailscaleGatewayExposureProvider::new(path, self.runner.clone());
            }
        }
        Err(GatewayExposureError::ProviderUnavailable)
    }
}

impl Default for SystemGatewayExposureProvider {
    // Creates the production lazy provider through the ordinary default boundary.
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayExposureProvider for SystemGatewayExposureProvider {
    // Discovers and enables through one exact trusted Tailscale executable.
    fn enable(&self) -> Result<GatewayExposure, GatewayExposureError> {
        self.provider()?.enable()
    }

    // Discovers and verifies through one exact trusted Tailscale executable.
    fn verify(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposure, GatewayExposureError> {
        self.provider()?.verify(expected_configuration_sha256)
    }

    // Discovers and disables through one exact trusted Tailscale executable.
    fn disable(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<(), GatewayExposureError> {
        self.provider()?.disable(expected_configuration_sha256)
    }
}

impl TailscaleGatewayExposureProvider {
    // Creates one provider only for an exact trusted Tailscale executable location.
    pub fn new(
        executable: PathBuf,
        runner: Arc<dyn GatewayExposureCommandRunner>,
    ) -> Result<Self, GatewayExposureError> {
        if !trusted_tailscale_path(&executable) {
            return Err(GatewayExposureError::InvalidConfiguration);
        }
        Ok(Self { executable, runner })
    }

    // Enables only an empty Funnel namespace and rolls back partial provider mutation.
    pub fn enable(&self) -> Result<GatewayExposure, GatewayExposureError> {
        if !self.status()?.is_empty() {
            return Err(GatewayExposureError::ProviderStateUnsafe);
        }
        let enabled = self.run(&[
            "funnel",
            "--bg",
            "--yes",
            "--https",
            "443",
            LETSINFER_PUBLIC_INFERENCE_TARGET,
        ])?;
        if !enabled.is_success() {
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        match self.observed_exposure() {
            Ok(exposure) => Ok(exposure),
            Err(error) => {
                let rollback = self.run(&["funnel", "reset"]);
                if rollback.is_err() || rollback.is_ok_and(|output| !output.is_success()) {
                    return Err(GatewayExposureError::RollbackIncomplete);
                }
                Err(error)
            }
        }
    }

    // Verifies live Funnel state against one exact previously committed identity.
    pub fn verify(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposure, GatewayExposureError> {
        let exposure = self.observed_exposure()?;
        if exposure.configuration_sha256() != expected_configuration_sha256 {
            return Err(GatewayExposureError::ProviderIdentityChanged);
        }
        Ok(exposure)
    }

    // Resets only the exact previously committed inference-owned Funnel configuration.
    pub fn disable(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<(), GatewayExposureError> {
        self.verify(expected_configuration_sha256)?;
        let reset = self.run(&["funnel", "reset"])?;
        if !reset.is_success() {
            return Err(GatewayExposureError::ProviderUnavailable);
        }
        if !self.status()?.is_empty() {
            return Err(GatewayExposureError::ProviderStateUnsafe);
        }
        Ok(())
    }

    // Reads and validates the complete live exposure identity.
    fn observed_exposure(&self) -> Result<GatewayExposure, GatewayExposureError> {
        let configuration = self.status()?;
        let configuration_sha256 = validate_owned_status(&configuration)?;
        let public_url = self.public_url()?;
        GatewayExposure::new(public_url, configuration_sha256)
    }

    // Reads one bounded Funnel status object.
    fn status(&self) -> Result<serde_json::Map<String, Value>, GatewayExposureError> {
        let output = self.run(&["funnel", "status", "--json"])?;
        parsed_object(&output)
    }

    // Reads and normalizes the active Tailscale DNS identity into one HTTPS origin.
    fn public_url(&self) -> Result<String, GatewayExposureError> {
        let output = self.run(&["status", "--json"])?;
        let value = parsed_object(&output)?;
        let dns_name = value
            .get("Self")
            .and_then(Value::as_object)
            .and_then(|value| value.get("DNSName"))
            .and_then(Value::as_str)
            .ok_or(GatewayExposureError::ProviderStateUnsafe)?;
        if !valid_dns_name(dns_name) {
            return Err(GatewayExposureError::ProviderStateUnsafe);
        }
        Ok(format!("https://{}", dns_name.trim_end_matches('.')))
    }

    // Runs one exact Tailscale argument vector through the injected native boundary.
    fn run(
        &self,
        arguments: &[&str],
    ) -> Result<GatewayExposureCommandOutput, GatewayExposureError> {
        self.runner
            .run(&GatewayExposureCommand::new(&self.executable, arguments))
    }
}

impl GatewayExposureProvider for TailscaleGatewayExposureProvider {
    // Enables one exact inference-only Tailscale Funnel configuration.
    fn enable(&self) -> Result<GatewayExposure, GatewayExposureError> {
        TailscaleGatewayExposureProvider::enable(self)
    }

    // Verifies the live Tailscale Funnel configuration against its committed digest.
    fn verify(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<GatewayExposure, GatewayExposureError> {
        TailscaleGatewayExposureProvider::verify(self, expected_configuration_sha256)
    }

    // Resets only the exact Tailscale Funnel configuration previously committed by Core.
    fn disable(
        &self,
        expected_configuration_sha256: &Sha256Digest,
    ) -> Result<(), GatewayExposureError> {
        TailscaleGatewayExposureProvider::disable(self, expected_configuration_sha256)
    }
}

// Parses one successful bounded provider response as a JSON object.
fn parsed_object(
    output: &GatewayExposureCommandOutput,
) -> Result<serde_json::Map<String, Value>, GatewayExposureError> {
    if !output.is_success() {
        return Err(GatewayExposureError::ProviderUnavailable);
    }
    match serde_json::from_slice::<Value>(output.standard_output()) {
        Ok(Value::Object(value)) => Ok(value),
        Ok(_) | Err(_) => Err(GatewayExposureError::ProviderStateUnsafe),
    }
}

// Validates the closed inference-only Funnel shape and returns its canonical identity.
fn validate_owned_status(
    value: &serde_json::Map<String, Value>,
) -> Result<Sha256Digest, GatewayExposureError> {
    let keys: Vec<&str> = value.keys().map(String::as_str).collect();
    if keys != ["AllowFunnel", "TCP", "Web"] {
        return Err(GatewayExposureError::ProviderStateUnsafe);
    }
    let expected_tcp = serde_json::json!({"443": {"HTTPS": true}});
    if value.get("TCP") != Some(&expected_tcp) {
        return Err(GatewayExposureError::ProviderStateUnsafe);
    }
    let web = value
        .get("Web")
        .and_then(Value::as_object)
        .filter(|value| value.len() == 1)
        .ok_or(GatewayExposureError::ProviderStateUnsafe)?;
    let (authority, website) = web
        .iter()
        .next()
        .ok_or(GatewayExposureError::ProviderStateUnsafe)?;
    if !authority.ends_with(":443")
        || website
            != &serde_json::json!({
                "Handlers": {"/": {"Proxy": LETSINFER_PUBLIC_INFERENCE_TARGET}}
            })
        || value.get("AllowFunnel") != Some(&serde_json::json!({authority: true}))
    {
        return Err(GatewayExposureError::ProviderStateUnsafe);
    }
    let canonical: BTreeMap<&str, &Value> = value
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    let bytes =
        serde_json::to_vec(&canonical).map_err(|_| GatewayExposureError::ProviderStateUnsafe)?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Sha256Digest::parse(&format!("{:x}", digest.finalize()))
        .map_err(|_| GatewayExposureError::ProviderStateUnsafe)
}

// Returns whether one bounded provider DNS name is a canonical trailing-dot host name.
fn valid_dns_name(value: &str) -> bool {
    value.len() <= 254
        && value.len() > 1
        && value.ends_with('.')
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

// Returns whether one executable path is one of the explicit trusted system locations.
fn trusted_tailscale_path(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some("/usr/bin/tailscale")
            | Some("/usr/local/bin/tailscale")
            | Some("/opt/homebrew/bin/tailscale")
    ) && path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.file_name() == Some(OsStr::new("tailscale"))
}

// Requires a trusted provider executable to remain an ordinary non-link file.
fn require_trusted_tailscale(path: &Path) -> Result<(), GatewayExposureError> {
    if !trusted_tailscale_path(path) {
        return Err(GatewayExposureError::InvalidConfiguration);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| GatewayExposureError::ProviderUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(GatewayExposureError::ProviderUnavailable);
    }
    Ok(())
}

// Drains one native output stream until EOF or the strict byte ceiling is exceeded.
fn read_bounded(stream: impl Read, maximum_bytes: usize) -> Result<Vec<u8>, GatewayExposureError> {
    let mut retained = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    stream
        .take((maximum_bytes as u64).saturating_add(1))
        .read_to_end(&mut retained)
        .map_err(|_| GatewayExposureError::ProviderUnavailable)?;
    if retained.len() > maximum_bytes {
        return Err(GatewayExposureError::ProviderUnavailable);
    }
    Ok(retained)
}

// Joins one bounded output worker without allowing a panic to escape the provider boundary.
fn join_output(
    worker: thread::JoinHandle<Result<Vec<u8>, GatewayExposureError>>,
) -> Result<Vec<u8>, GatewayExposureError> {
    worker
        .join()
        .map_err(|_| GatewayExposureError::ProviderUnavailable)?
}

// Reaps one killed provider process inside the fixed cleanup deadline.
fn wait_for_exit(child: &mut std::process::Child) -> Result<i32, GatewayExposureError> {
    let deadline = Instant::now()
        .checked_add(PROVIDER_CLEANUP_TIMEOUT)
        .ok_or(GatewayExposureError::ProviderUnavailable)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
            Ok(None) if Instant::now() < deadline => thread::sleep(PROVIDER_POLL_INTERVAL),
            Ok(None) | Err(_) => return Err(GatewayExposureError::ProviderUnavailable),
        }
    }
}
