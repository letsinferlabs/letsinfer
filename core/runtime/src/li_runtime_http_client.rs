// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::RuntimeError;

const MAX_RESPONSE_HEADERS: usize = 256 * 1024;
const MAX_MOCK_RESPONSE_BODY: usize = 16 * 1024 * 1024;
const MAX_COMMAND_OUTPUT: usize = 4 * 1024;
const MAX_REDIRECTS: u8 = 5;
const DEFAULT_CONNECT_TIMEOUT_SECONDS: u16 = 30;
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u32 = 3_600;
const USER_AGENT: &str = "letsinfer/rust-core-v1";

// Stores one ephemeral bearer token without exposing it through diagnostics.
pub struct RuntimeBearerToken(Vec<u8>);

impl RuntimeBearerToken {
    // Creates one bounded non-whitespace bearer token from a trusted challenge response.
    pub fn new(value: &str) -> Result<Self, RuntimeError> {
        if value.is_empty()
            || value.len() > 16 * 1024
            || value.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'"' | b'\\')
            })
        {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok(Self(value.as_bytes().to_vec()))
    }

    // Returns the secret only to the private authorization-file writer.
    fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for RuntimeBearerToken {
    // Copies one ephemeral token for a single retry scope.
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for RuntimeBearerToken {
    // Redacts bearer token bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeBearerToken([REDACTED])")
    }
}

impl Drop for RuntimeBearerToken {
    // Clears bearer token bytes before releasing their allocation.
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

// Describes one bounded immutable HTTP GET without embedding credentials in its URL.
#[derive(Clone, Debug)]
pub struct RuntimeHttpRequest {
    url: String,
    accept: Option<String>,
    bearer_token: Option<RuntimeBearerToken>,
    allow_loopback_http: bool,
    timeout_seconds: u32,
}

impl RuntimeHttpRequest {
    // Creates one credential-free HTTPS request with optional local-development transport.
    pub fn new(
        url: &str,
        accept: Option<String>,
        bearer_token: Option<RuntimeBearerToken>,
        allow_loopback_http: bool,
        timeout_seconds: u32,
    ) -> Result<Self, RuntimeError> {
        validate_url(url, allow_loopback_http)?;
        if timeout_seconds == 0
            || timeout_seconds > 7 * 24 * 60 * 60
            || accept.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 2_048
                    || value
                        .chars()
                        .any(|character| character.is_control() || matches!(character, '\r' | '\n'))
            })
        {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok(Self {
            url: url.to_string(),
            accept,
            bearer_token,
            allow_loopback_http,
            timeout_seconds,
        })
    }

    // Creates the ordinary bounded HTTPS metadata request.
    pub fn https(url: &str, accept: Option<String>) -> Result<Self, RuntimeError> {
        Self::new(url, accept, None, false, DEFAULT_REQUEST_TIMEOUT_SECONDS)
    }

    // Returns the exact request URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    // Returns the optional accepted response media types.
    pub fn accept(&self) -> Option<&str> {
        self.accept.as_deref()
    }

    // Returns whether loopback HTTP is explicitly permitted.
    pub const fn allows_loopback_http(&self) -> bool {
        self.allow_loopback_http
    }

    // Returns whether authorization is supplied through a private configuration file.
    pub const fn has_bearer_token(&self) -> bool {
        self.bearer_token.is_some()
    }
}

// Returns one bounded HTTP metadata response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHttpResponse {
    status: u16,
    final_url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RuntimeHttpResponse {
    // Creates one bounded response for deterministic higher-level protocol mocks.
    pub fn new(
        status: u16,
        final_url: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        allow_loopback_http: bool,
    ) -> Result<Self, RuntimeError> {
        if !(100..=599).contains(&status) || body.len() > MAX_MOCK_RESPONSE_BODY {
            return Err(RuntimeError::DownloadInvalid);
        }
        validate_url(&final_url, allow_loopback_http)?;
        validate_header_map(&headers)?;
        Ok(Self {
            status,
            final_url,
            headers,
            body,
        })
    }

    // Returns the final HTTP response status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    // Returns the final transport URL after bounded redirects.
    pub fn final_url(&self) -> &str {
        &self.final_url
    }

    // Returns one normalized final-response header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    // Returns the bounded response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

// Returns one exact streamed download identity without retaining its bytes in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHttpDownload {
    status: u16,
    final_url: String,
    headers: BTreeMap<String, String>,
    bytes: u64,
    sha256: Sha256Digest,
}

impl RuntimeHttpDownload {
    // Creates one measured download result for deterministic higher-level protocol mocks.
    pub fn new(
        status: u16,
        final_url: String,
        headers: BTreeMap<String, String>,
        bytes: u64,
        sha256: Sha256Digest,
        allow_loopback_http: bool,
    ) -> Result<Self, RuntimeError> {
        if !(100..=599).contains(&status) {
            return Err(RuntimeError::DownloadInvalid);
        }
        validate_url(&final_url, allow_loopback_http)?;
        validate_header_map(&headers)?;
        Ok(Self {
            status,
            final_url,
            headers,
            bytes,
            sha256,
        })
    }

    // Returns the final HTTP response status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    // Returns the final transport URL after bounded redirects.
    pub fn final_url(&self) -> &str {
        &self.final_url
    }

    // Returns one normalized final-response header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    // Returns the exact downloaded byte count.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    // Returns the exact downloaded SHA-256.
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

// Defines bounded metadata and streamed download operations consumed by acquisition providers.
pub trait RuntimeHttpClient: Send + Sync {
    // Returns only final response metadata for one bounded HEAD request.
    fn head(&self, _request: &RuntimeHttpRequest) -> Result<RuntimeHttpResponse, RuntimeError> {
        Err(RuntimeError::DownloadUnavailable)
    }

    // Returns one bounded response body and final response metadata.
    fn get(
        &self,
        request: &RuntimeHttpRequest,
        maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpResponse, RuntimeError>;

    // Streams one bounded response to a new exact destination.
    fn download(
        &self,
        request: &RuntimeHttpRequest,
        destination: &Path,
        maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpDownload, RuntimeError>;
}

// Carries one exact shell-free native HTTP command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHttpCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    working_directory: PathBuf,
}

impl RuntimeHttpCommand {
    // Creates one absolute shell-free HTTP command with bounded argv.
    pub fn new(
        executable: PathBuf,
        arguments: Vec<String>,
        working_directory: PathBuf,
    ) -> Result<Self, RuntimeError> {
        if !is_safe_absolute_path(&executable)
            || !is_safe_absolute_path(&working_directory)
            || arguments.is_empty()
            || arguments.len() > 128
            || arguments.iter().map(String::len).sum::<usize>() > 32 * 1024
            || arguments.iter().any(|value| {
                value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control)
            })
        {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok(Self {
            executable,
            arguments,
            working_directory,
        })
    }

    // Returns the exact executable path.
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    // Returns exact argv without an executable token.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    // Returns the private working directory.
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }
}

// Carries one bounded native command result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeHttpCommandOutput {
    status: i32,
    stdout: Vec<u8>,
}

impl RuntimeHttpCommandOutput {
    // Creates one exact command result for production or deterministic mocks.
    pub const fn new(status: i32, stdout: Vec<u8>) -> Self {
        Self { status, stdout }
    }

    // Returns the process exit status or -1 after signal termination.
    pub const fn status(&self) -> i32 {
        self.status
    }

    // Returns bounded standard output used only for status and final URL.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

// Defines shell-free native process execution behind one deterministic boundary.
pub trait RuntimeHttpCommandRunner: Send + Sync {
    // Executes one exact command and bounds its standard output.
    fn run(
        &self,
        command: &RuntimeHttpCommand,
        maximum_stdout_bytes: usize,
    ) -> Result<RuntimeHttpCommandOutput, RuntimeError>;
}

// Executes curl directly without a shell, inherited stdin, or retained stderr.
pub struct SystemRuntimeHttpCommandRunner;

impl RuntimeHttpCommandRunner for SystemRuntimeHttpCommandRunner {
    // Executes one exact command with a closed process environment.
    fn run(
        &self,
        command: &RuntimeHttpCommand,
        maximum_stdout_bytes: usize,
    ) -> Result<RuntimeHttpCommandOutput, RuntimeError> {
        let output = Command::new(command.executable())
            .args(command.arguments())
            .current_dir(command.working_directory())
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .output()
            .map_err(|_| RuntimeError::DownloadUnavailable)?;
        if output.stdout.len() > maximum_stdout_bytes {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok(RuntimeHttpCommandOutput::new(
            output.status.code().unwrap_or(-1),
            output.stdout,
        ))
    }
}

// Supplies collision-resistant request workspace identities explicitly.
pub trait RuntimeHttpIdentityProvider: Send + Sync {
    // Returns one lowercase 32-hex request identity.
    fn request_id(&self) -> Result<String, RuntimeError>;
}

// Generates request identities from operating-system entropy.
pub struct RandomRuntimeHttpIdentityProvider;

impl RuntimeHttpIdentityProvider for RandomRuntimeHttpIdentityProvider {
    // Returns one random 128-bit request identity.
    fn request_id(&self) -> Result<String, RuntimeError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeError::DownloadUnavailable)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

// Defines private request workspace and downloaded-file operations.
pub trait RuntimeHttpWorkspaceIo: Send + Sync {
    // Creates one exact private request workspace.
    fn create_workspace(&self, path: &Path) -> Result<(), RuntimeError>;

    // Writes one private curl authorization configuration.
    fn write_authorization(
        &self,
        path: &Path,
        token: &RuntimeBearerToken,
    ) -> Result<(), RuntimeError>;

    // Reads one bounded regular file.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError>;

    // Returns exact size and SHA-256 for one regular file.
    fn identity(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<(u64, Sha256Digest), RuntimeError>;

    // Atomically moves one request body into its final new destination.
    fn activate(&self, source: &Path, destination: &Path) -> Result<(), RuntimeError>;

    // Removes one exact request workspace and every private temporary file.
    fn remove_workspace(&self, path: &Path) -> Result<(), RuntimeError>;
}

// Implements private no-follow request workspace operations on the host filesystem.
pub struct SystemRuntimeHttpWorkspaceIo;

impl RuntimeHttpWorkspaceIo for SystemRuntimeHttpWorkspaceIo {
    // Creates one new owner-only request workspace.
    fn create_workspace(&self, path: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(path.parent().ok_or(RuntimeError::DownloadInvalid)?)?;
        fs::create_dir(path).map_err(|_| RuntimeError::DownloadUnavailable)?;
        set_mode(path, 0o700)
    }

    // Writes authorization only to one owner-readable no-follow file.
    fn write_authorization(
        &self,
        path: &Path,
        token: &RuntimeBearerToken,
    ) -> Result<(), RuntimeError> {
        let mut file = create_new_file(path, 0o600)?;
        file.write_all(b"header = \"Authorization: Bearer ")
            .and_then(|_| file.write_all(token.value()))
            .and_then(|_| file.write_all(b"\"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| RuntimeError::DownloadUnavailable)
    }

    // Reads one bounded regular file without following the final path.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
        let mut file = open_no_follow(path)?;
        validate_private_file(&file, maximum_bytes as u64, false)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RuntimeError::DownloadUnavailable)?;
        if bytes.len() > maximum_bytes {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok(bytes)
    }

    // Hashes one bounded regular file without following the final path.
    fn identity(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<(u64, Sha256Digest), RuntimeError> {
        let mut file = open_no_follow(path)?;
        let bytes = validate_private_file(&file, maximum_bytes, false)?;
        let mut digest = Sha256::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| RuntimeError::DownloadUnavailable)?;
            if count == 0 {
                break;
            }
            observed = observed
                .checked_add(count as u64)
                .ok_or(RuntimeError::DownloadInvalid)?;
            if observed > maximum_bytes {
                return Err(RuntimeError::DownloadInvalid);
            }
            digest.update(&buffer[..count]);
        }
        if observed != bytes {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok((observed, sha256_digest(digest.finalize().as_slice())))
    }

    // Activates one exact file without overwriting an existing destination.
    fn activate(&self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        if destination.exists() || destination.is_symlink() {
            return Err(RuntimeError::DownloadInvalid);
        }
        let file = open_no_follow(source)?;
        validate_private_file(&file, u64::MAX, false)?;
        drop(file);
        let parent = destination.parent().ok_or(RuntimeError::DownloadInvalid)?;
        validate_private_directory(parent)?;
        fs::rename(source, destination).map_err(|_| RuntimeError::DownloadUnavailable)
    }

    // Removes only one canonical non-symlink request workspace.
    fn remove_workspace(&self, path: &Path) -> Result<(), RuntimeError> {
        if path.is_symlink() || !path.is_dir() {
            return Err(RuntimeError::DownloadInvalid);
        }
        fs::remove_dir_all(path).map_err(|_| RuntimeError::DownloadUnavailable)
    }
}

// Owns fixed curl invocation, private bearer configuration, and exact response parsing.
pub struct CurlRuntimeHttpClient {
    curl: PathBuf,
    workspace_root: PathBuf,
    runner: Arc<dyn RuntimeHttpCommandRunner>,
    identity: Arc<dyn RuntimeHttpIdentityProvider>,
    io: Arc<dyn RuntimeHttpWorkspaceIo>,
}

impl CurlRuntimeHttpClient {
    // Creates one client from explicit executable, workspace, process, identity, and I/O ports.
    pub fn new(
        curl: PathBuf,
        workspace_root: PathBuf,
        runner: Arc<dyn RuntimeHttpCommandRunner>,
        identity: Arc<dyn RuntimeHttpIdentityProvider>,
        io: Arc<dyn RuntimeHttpWorkspaceIo>,
    ) -> Result<Self, RuntimeError> {
        if !is_safe_absolute_path(&curl)
            || !is_safe_absolute_path(&workspace_root)
            || curl == workspace_root
        {
            return Err(RuntimeError::DownloadInvalid);
        }
        Ok(Self {
            curl,
            workspace_root,
            runner,
            identity,
            io,
        })
    }

    // Performs one request into a private workspace and returns parsed response metadata.
    fn perform(
        &self,
        request: &RuntimeHttpRequest,
        maximum_body_bytes: u64,
        head: bool,
    ) -> Result<PerformedRequest, RuntimeError> {
        if maximum_body_bytes == 0 || maximum_body_bytes > (1_u64 << 40) {
            return Err(RuntimeError::DownloadInvalid);
        }
        let request_id = self.identity.request_id()?;
        if !is_lower_hex(&request_id, 32) {
            return Err(RuntimeError::DownloadInvalid);
        }
        let workspace = self.workspace_root.join(format!("li_http_{request_id}"));
        self.io.create_workspace(&workspace)?;
        let body = workspace.join("li_http_body");
        let headers = workspace.join("li_http_headers");
        let authorization = workspace.join("li_http_authorization");
        let result = (|| {
            if let Some(token) = &request.bearer_token {
                self.io.write_authorization(&authorization, token)?;
            }
            let command = self.command(
                request,
                maximum_body_bytes,
                &workspace,
                &body,
                &headers,
                request
                    .bearer_token
                    .as_ref()
                    .map(|_| authorization.as_path()),
                head,
            )?;
            let output = self.runner.run(&command, MAX_COMMAND_OUTPUT)?;
            if output.status() != 0 {
                return Err(RuntimeError::DownloadUnavailable);
            }
            let (status, final_url) = parse_command_output(output.stdout())?;
            validate_url(&final_url, request.allow_loopback_http)?;
            let header_bytes = self.io.read(&headers, MAX_RESPONSE_HEADERS)?;
            let headers = parse_final_headers(&header_bytes, status)?;
            Ok(PerformedRequest {
                workspace: workspace.clone(),
                body,
                status,
                final_url,
                headers,
            })
        })();
        if result.is_err() {
            let _ = self.io.remove_workspace(&workspace);
        }
        result
    }

    // Builds fixed curl argv while keeping bearer bytes outside the process list.
    #[allow(clippy::too_many_arguments)]
    fn command(
        &self,
        request: &RuntimeHttpRequest,
        maximum_body_bytes: u64,
        workspace: &Path,
        body: &Path,
        headers: &Path,
        authorization: Option<&Path>,
        head: bool,
    ) -> Result<RuntimeHttpCommand, RuntimeError> {
        let protocol = if request.allow_loopback_http {
            "=http,https"
        } else {
            "=https"
        };
        let mut arguments = vec![
            "--disable".to_string(),
            "--silent".to_string(),
            "--show-error".to_string(),
            "--proto".to_string(),
            protocol.to_string(),
            "--connect-timeout".to_string(),
            DEFAULT_CONNECT_TIMEOUT_SECONDS.to_string(),
            "--max-time".to_string(),
            request.timeout_seconds.to_string(),
            "--max-filesize".to_string(),
            maximum_body_bytes.to_string(),
            "--user-agent".to_string(),
            USER_AGENT.to_string(),
            "--dump-header".to_string(),
            path_string(headers)?.to_string(),
            "--output".to_string(),
            path_string(body)?.to_string(),
            "--write-out".to_string(),
            "%{http_code}\\n%{url_effective}".to_string(),
        ];
        if request.bearer_token.is_none() {
            arguments.extend([
                "--location".to_string(),
                "--max-redirs".to_string(),
                MAX_REDIRECTS.to_string(),
                "--proto-redir".to_string(),
                protocol.to_string(),
            ]);
        }
        if let Some(accept) = request.accept() {
            arguments.extend(["--header".to_string(), format!("Accept: {accept}")]);
        }
        if head {
            arguments.push("--head".to_string());
        }
        if let Some(authorization) = authorization {
            arguments.extend([
                "--config".to_string(),
                path_string(authorization)?.to_string(),
            ]);
        }
        arguments.extend(["--url".to_string(), request.url().to_string()]);
        RuntimeHttpCommand::new(self.curl.clone(), arguments, workspace.to_path_buf())
    }
}

impl RuntimeHttpClient for CurlRuntimeHttpClient {
    // Returns bounded final response metadata without retaining a response body.
    fn head(&self, request: &RuntimeHttpRequest) -> Result<RuntimeHttpResponse, RuntimeError> {
        let performed = self.perform(request, 1024 * 1024, true)?;
        let result = RuntimeHttpResponse::new(
            performed.status,
            performed.final_url.clone(),
            performed.headers.clone(),
            Vec::new(),
            request.allow_loopback_http,
        );
        let cleanup = self.io.remove_workspace(&performed.workspace);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    // Returns one bounded metadata body and removes all request workspace material.
    fn get(
        &self,
        request: &RuntimeHttpRequest,
        maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpResponse, RuntimeError> {
        let performed = self.perform(request, maximum_body_bytes, false)?;
        let result = (|| {
            let maximum =
                usize::try_from(maximum_body_bytes).map_err(|_| RuntimeError::DownloadInvalid)?;
            let body = self.io.read(&performed.body, maximum)?;
            RuntimeHttpResponse::new(
                performed.status,
                performed.final_url.clone(),
                performed.headers.clone(),
                body,
                request.allow_loopback_http,
            )
        })();
        let cleanup = self.io.remove_workspace(&performed.workspace);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    // Activates one successful bounded download and removes every request temporary.
    fn download(
        &self,
        request: &RuntimeHttpRequest,
        destination: &Path,
        maximum_body_bytes: u64,
    ) -> Result<RuntimeHttpDownload, RuntimeError> {
        if !is_safe_absolute_path(destination) {
            return Err(RuntimeError::DownloadInvalid);
        }
        let performed = self.perform(request, maximum_body_bytes, false)?;
        let result = (|| {
            let (bytes, sha256) = self.io.identity(&performed.body, maximum_body_bytes)?;
            if !(200..=299).contains(&performed.status) {
                return Err(RuntimeError::DownloadUnavailable);
            }
            self.io.activate(&performed.body, destination)?;
            RuntimeHttpDownload::new(
                performed.status,
                performed.final_url.clone(),
                performed.headers.clone(),
                bytes,
                sha256,
                request.allow_loopback_http,
            )
        })();
        let cleanup = self.io.remove_workspace(&performed.workspace);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

// Carries one successful private request before body consumption or activation.
struct PerformedRequest {
    workspace: PathBuf,
    body: PathBuf,
    status: u16,
    final_url: String,
    headers: BTreeMap<String, String>,
}

// Parses curl's fixed status and effective-URL output contract.
fn parse_command_output(bytes: &[u8]) -> Result<(u16, String), RuntimeError> {
    let value = std::str::from_utf8(bytes).map_err(|_| RuntimeError::DownloadInvalid)?;
    let mut lines = value.lines();
    let status = lines
        .next()
        .ok_or(RuntimeError::DownloadInvalid)?
        .parse::<u16>()
        .map_err(|_| RuntimeError::DownloadInvalid)?;
    let final_url = lines
        .next()
        .ok_or(RuntimeError::DownloadInvalid)?
        .to_string();
    if !(100..=599).contains(&status) || lines.next().is_some() {
        return Err(RuntimeError::DownloadInvalid);
    }
    Ok((status, final_url))
}

// Parses only the final HTTP header block matching curl's final response status.
fn parse_final_headers(
    bytes: &[u8],
    expected_status: u16,
) -> Result<BTreeMap<String, String>, RuntimeError> {
    let value = std::str::from_utf8(bytes).map_err(|_| RuntimeError::DownloadInvalid)?;
    let normalized = value.replace("\r\n", "\n");
    let block = normalized
        .split("\n\n")
        .filter(|block| block.starts_with("HTTP/"))
        .last()
        .ok_or(RuntimeError::DownloadInvalid)?;
    let mut lines = block.lines();
    let status_line = lines.next().ok_or(RuntimeError::DownloadInvalid)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(RuntimeError::DownloadInvalid)?;
    if status != expected_status {
        return Err(RuntimeError::DownloadInvalid);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(RuntimeError::DownloadInvalid)?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name.is_empty()
            || name.len() > 256
            || value.len() > 16 * 1024
            || name.chars().any(|character| {
                !(character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-')
            })
            || value.chars().any(char::is_control)
        {
            return Err(RuntimeError::DownloadInvalid);
        }
        headers.insert(name, value.to_string());
    }
    Ok(headers)
}

// Validates normalized bounded response headers supplied by deterministic mocks.
fn validate_header_map(headers: &BTreeMap<String, String>) -> Result<(), RuntimeError> {
    if headers.len() > 256
        || headers.iter().any(|(name, value)| {
            name.is_empty()
                || name.len() > 256
                || name != &name.to_ascii_lowercase()
                || value.len() > 16 * 1024
                || name.chars().any(|character| {
                    !(character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || character == '-')
                })
                || value.chars().any(char::is_control)
        })
    {
        return Err(RuntimeError::DownloadInvalid);
    }
    Ok(())
}

// Validates credential-free HTTPS or explicitly local loopback HTTP URLs.
fn validate_url(value: &str, allow_loopback_http: bool) -> Result<(), RuntimeError> {
    if value.is_empty()
        || value.len() > 8 * 1024
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains('@')
        || value.contains('#')
    {
        return Err(RuntimeError::DownloadInvalid);
    }
    let https = value.strip_prefix("https://");
    let is_https = https.is_some();
    let loopback = value
        .strip_prefix("http://")
        .filter(|_| allow_loopback_http);
    let remainder = https.or(loopback).ok_or(RuntimeError::DownloadInvalid)?;
    let authority = remainder.split('/').next().unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default();
    if authority.is_empty() || (!is_https && !matches!(host, "127.0.0.1" | "localhost")) {
        return Err(RuntimeError::DownloadInvalid);
    }
    Ok(())
}

// Returns whether one absolute path has no parent or platform-prefix ambiguity.
fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// Returns one UTF-8 path without lossy conversion.
fn path_string(path: &Path) -> Result<&str, RuntimeError> {
    path.to_str().ok_or(RuntimeError::DownloadInvalid)
}

// Returns whether one identity is exact lowercase hexadecimal text.
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Creates one no-follow owner-only file with exact Unix mode.
fn create_new_file(path: &Path, mode: u32) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| RuntimeError::DownloadUnavailable)
}

// Opens one existing regular file without following the final path.
fn open_no_follow(path: &Path) -> Result<File, RuntimeError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| RuntimeError::DownloadUnavailable)
}

// Requires one regular user-owned non-writable bounded file.
fn validate_private_file(
    file: &File,
    maximum_bytes: u64,
    require_nonempty: bool,
) -> Result<u64, RuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::DownloadUnavailable)?;
    if !metadata.is_file()
        || metadata.len() > maximum_bytes
        || (require_nonempty && metadata.len() == 0)
    {
        return Err(RuntimeError::DownloadInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(RuntimeError::DownloadInvalid);
        }
    }
    Ok(metadata.len())
}

// Requires one no-follow owner-only directory for private HTTP material.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::DownloadUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::DownloadInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::DownloadInvalid);
        }
    }
    Ok(())
}

// Sets one exact owner-controlled Unix mode.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| RuntimeError::DownloadUnavailable)
}

// Leaves modes to the future Windows provider.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), RuntimeError> {
    Ok(())
}

// Converts one finalized SHA-256 into the shared identity type.
fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(
        &bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("SHA-256 encoder produces one canonical digest")
}
