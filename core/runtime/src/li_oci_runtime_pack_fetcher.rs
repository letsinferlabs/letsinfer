// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use li_core_interface::{RuntimeSource, Sha256Digest};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    li_runtime_catalog_schema::parse_closed_json, RuntimeBearerToken, RuntimeError,
    RuntimeHttpClient, RuntimeHttpRequest, RuntimeHttpResponse, RuntimePackArtifactFetcher,
};

const OCI_MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.artifact.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_ARTIFACT_MANIFEST: &str = "application/vnd.oci.artifact.manifest.v1+json";
const DOCKER_IMAGE_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const PACK_MEDIA_TYPE: &str = "application/vnd.letsinfer.runtime.v6+tar";
const RUNTIME_DESCRIPTOR: &str = "letsinfer-runtime.json";
const RUNTIME_CONFIG: &str = "runtime.json";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOKEN_BYTES: u64 = 1024 * 1024;
const MAX_PACK_BYTES: u64 = 1 << 30;
const MAX_PACK_FILES: usize = 10_000;
const MAX_PROTOCOL_STEPS: usize = 12;

// Carries the exact verified documents needed to hydrate one runtime candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePackDocuments {
    descriptor_digest: Sha256Digest,
    descriptor: Vec<u8>,
    runtime: Vec<u8>,
}

impl RuntimePackDocuments {
    // Creates one document set supplied by an already verified pack-provider capability.
    pub fn from_verified(
        descriptor_digest: Sha256Digest,
        descriptor: Vec<u8>,
        runtime: Vec<u8>,
    ) -> Self {
        Self {
            descriptor_digest,
            descriptor,
            runtime,
        }
    }

    // Returns the canonical descriptor identity bound by runtime persistence.
    pub const fn descriptor_digest(&self) -> &Sha256Digest {
        &self.descriptor_digest
    }

    // Returns the exact descriptor bytes acquired from the immutable OCI layer.
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }

    // Returns the exact schema-6 runtime bytes acquired from the immutable OCI layer.
    pub fn runtime(&self) -> &[u8] {
        &self.runtime
    }
}

// Defines private runtime-pack extraction and descriptor verification operations.
pub trait RuntimePackArtifactIo: Send + Sync {
    // Requires one empty private runtime-pack destination.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError>;

    // Extracts one bounded regular-file-only deterministic runtime archive.
    fn extract_archive(&self, archive: &Path, destination: &Path) -> Result<(), RuntimeError>;

    // Removes one exact downloaded archive after successful extraction.
    fn remove_archive(&self, archive: &Path) -> Result<(), RuntimeError>;

    // Verifies the complete descriptor, file inventory, modes, bytes, and digest.
    fn verify_descriptor(
        &self,
        destination: &Path,
        expected_digest: &Sha256Digest,
    ) -> Result<(), RuntimeError>;

    // Returns exact documents only after verifying the complete self-described closure.
    fn verified_documents(&self, destination: &Path) -> Result<RuntimePackDocuments, RuntimeError>;

    // Removes every contained acquisition entry while retaining the destination root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError>;
}

// Implements bounded no-follow runtime-pack extraction and verification on the host filesystem.
pub struct SystemRuntimePackArtifactIo;

impl RuntimePackArtifactIo for SystemRuntimePackArtifactIo {
    // Requires one owner-only empty destination created by RuntimeManager staging.
    fn prepare_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        if destination
            .read_dir()
            .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?
            .next()
            .is_some()
        {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        Ok(())
    }

    // Extracts only canonical regular entries under the exact destination.
    fn extract_archive(&self, archive: &Path, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        let file = open_no_follow(archive)?;
        let mut archive = tar::Archive::new(file);
        let mut entries = archive
            .entries()
            .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
        let mut seen = HashSet::new();
        let mut total = 0_u64;
        let mut count = 0_usize;
        while let Some(entry) = entries.next() {
            let mut entry = entry.map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
            count += 1;
            if count > MAX_PACK_FILES + 1 || !entry.header().entry_type().is_file() {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            let relative = safe_relative(
                entry
                    .path()
                    .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?
                    .as_ref(),
            )?;
            if !seen.insert(relative.clone()) {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            let bytes = entry
                .header()
                .size()
                .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
            total = total
                .checked_add(bytes)
                .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
            if total > MAX_PACK_BYTES {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            let mode = entry
                .header()
                .mode()
                .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?
                & 0o777;
            if !matches!(mode, 0o644 | 0o755) {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            let target = destination.join(&relative);
            create_private_parents(
                destination,
                relative.parent().unwrap_or_else(|| Path::new("")),
            )?;
            let mut output = create_new_file(&target, mode)?;
            let copied = std::io::copy(&mut entry, &mut output)
                .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
            if copied != bytes {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            output
                .sync_all()
                .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
            set_mode(&target, mode)?;
        }
        if count == 0 || !seen.contains(Path::new(RUNTIME_DESCRIPTOR)) {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        Ok(())
    }

    // Removes one exact no-follow regular archive file.
    fn remove_archive(&self, archive: &Path) -> Result<(), RuntimeError> {
        let metadata = fs::symlink_metadata(archive)
            .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        fs::remove_file(archive).map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)
    }

    // Verifies descriptor identity and every exact file without trusting extraction state.
    fn verify_descriptor(
        &self,
        destination: &Path,
        expected_digest: &Sha256Digest,
    ) -> Result<(), RuntimeError> {
        let documents = verified_runtime_documents(destination)?;
        if documents.descriptor_digest() != expected_digest {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        Ok(())
    }

    // Returns descriptor and runtime bytes only after the complete pack closure verifies.
    fn verified_documents(&self, destination: &Path) -> Result<RuntimePackDocuments, RuntimeError> {
        verified_runtime_documents(destination)
    }

    // Removes only regular files and private directories below the exact root.
    fn clear_destination(&self, destination: &Path) -> Result<(), RuntimeError> {
        validate_private_directory(destination)?;
        clear_directory(destination)
    }
}

// Acquires one exact public OCI runtime pack and verifies its complete source closure.
pub struct OciRuntimePackFetcher {
    http: Arc<dyn RuntimeHttpClient>,
    io: Arc<dyn RuntimePackArtifactIo>,
}

impl OciRuntimePackFetcher {
    // Creates one OCI fetcher from explicit HTTP and private-filesystem capabilities.
    pub const fn new(http: Arc<dyn RuntimeHttpClient>, io: Arc<dyn RuntimePackArtifactIo>) -> Self {
        Self { http, io }
    }

    // Resolves and verifies one OCI manifest plus its single runtime-pack layer.
    fn acquire(
        &self,
        source: &RuntimeSource,
        runtime_digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        let documents = self.acquire_documents(source, destination)?;
        if documents.descriptor_digest() != runtime_digest {
            let _ = self.io.clear_destination(destination);
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        Ok(())
    }

    // Resolves one immutable OCI pack and returns its fully verified candidate documents.
    fn acquire_documents(
        &self,
        source: &RuntimeSource,
        destination: &Path,
    ) -> Result<RuntimePackDocuments, RuntimeError> {
        self.io.prepare_destination(destination)?;
        let reference = OciReference::parse(source)?;
        let result = (|| {
            let manifest_url = reference.manifest_url();
            let (response, token) = self.authenticated_get(
                &manifest_url,
                Some(OCI_MANIFEST_ACCEPT.to_string()),
                &reference,
            )?;
            if response.status() != 200 || sha256(response.body()) != reference.manifest_digest {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            let layer = parse_manifest(response.body())?;
            let blob_url = reference.blob_url(&layer.digest);
            let (head, blob_token) = self.authenticated_head(&blob_url, token, &reference)?;
            if head.status() != 200 {
                return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
            }
            if head
                .header("content-length")
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?
                .is_some_and(|bytes| bytes != layer.bytes)
            {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            let archive = destination.join(".li_runtime_archive");
            let request = RuntimeHttpRequest::new(
                head.final_url(),
                Some(layer.media_type.clone()),
                blob_token,
                reference.allow_loopback_http,
                7 * 24 * 60 * 60,
            )
            .map_err(map_download_error)?;
            let download = self
                .http
                .download(&request, &archive, layer.bytes)
                .map_err(map_download_error)?;
            if download.bytes() != layer.bytes || download.sha256() != &layer.digest {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            self.io.extract_archive(&archive, destination)?;
            self.io.remove_archive(&archive)?;
            self.io.verified_documents(destination)
        })();
        if result.is_err() {
            let _ = self.io.clear_destination(destination);
        }
        result
    }

    // Materializes one immutable OCI pack for catalog hydration without trusting its descriptor.
    pub fn documents(
        &self,
        source: &RuntimeSource,
        destination: &Path,
    ) -> Result<RuntimePackDocuments, RuntimeError> {
        self.acquire_documents(source, destination)
    }

    // Clears one exact hydration workspace through the injected safe filesystem capability.
    pub fn clear(&self, destination: &Path) -> Result<(), RuntimeError> {
        self.io.clear_destination(destination)
    }

    // Performs bounded public bearer authentication for one metadata GET.
    fn authenticated_get(
        &self,
        initial_url: &str,
        accept: Option<String>,
        reference: &OciReference,
    ) -> Result<(RuntimeHttpResponse, Option<RuntimeBearerToken>), RuntimeError> {
        let mut url = initial_url.to_string();
        let mut token = None;
        let mut authentication_attempts = 0_u8;
        for _step in 0..MAX_PROTOCOL_STEPS {
            let request = RuntimeHttpRequest::new(
                &url,
                accept.clone(),
                token.clone(),
                reference.allow_loopback_http,
                60,
            )
            .map_err(map_download_error)?;
            let response = self
                .http
                .get(&request, MAX_MANIFEST_BYTES)
                .map_err(map_download_error)?;
            match response.status() {
                401 | 403 if authentication_attempts < 2 => {
                    authentication_attempts += 1;
                    token = Some(self.public_token(
                        response.header("www-authenticate"),
                        &reference.repository,
                    )?);
                    url = response.final_url().to_string();
                }
                301 | 302 | 303 | 307 | 308 => {
                    url = resolve_redirect(
                        response.final_url(),
                        response
                            .header("location")
                            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?,
                        reference.allow_loopback_http,
                    )?;
                    token = None;
                }
                _ => return Ok((response, token)),
            }
        }
        Err(RuntimeError::RuntimePackAcquisitionInvalid)
    }

    // Performs bounded bearer authentication and manual token-safe redirects for one blob HEAD.
    fn authenticated_head(
        &self,
        initial_url: &str,
        initial_token: Option<RuntimeBearerToken>,
        reference: &OciReference,
    ) -> Result<(RuntimeHttpResponse, Option<RuntimeBearerToken>), RuntimeError> {
        let mut url = initial_url.to_string();
        let mut token = initial_token;
        let mut authentication_attempts = 0_u8;
        for _step in 0..MAX_PROTOCOL_STEPS {
            let request = RuntimeHttpRequest::new(
                &url,
                None,
                token.clone(),
                reference.allow_loopback_http,
                60,
            )
            .map_err(map_download_error)?;
            let response = self.http.head(&request).map_err(map_download_error)?;
            match response.status() {
                401 | 403 if authentication_attempts < 2 => {
                    authentication_attempts += 1;
                    token = Some(self.public_token(
                        response.header("www-authenticate"),
                        &reference.repository,
                    )?);
                    url = response.final_url().to_string();
                }
                301 | 302 | 303 | 307 | 308 => {
                    url = resolve_redirect(
                        response.final_url(),
                        response
                            .header("location")
                            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?,
                        reference.allow_loopback_http,
                    )?;
                    token = None;
                }
                _ => return Ok((response, token)),
            }
        }
        Err(RuntimeError::RuntimePackAcquisitionInvalid)
    }

    // Resolves one public registry challenge into an ephemeral pull-scoped bearer token.
    fn public_token(
        &self,
        challenge: Option<&str>,
        repository: &str,
    ) -> Result<RuntimeBearerToken, RuntimeError> {
        let parameters = parse_bearer_challenge(challenge)?;
        let realm = parameters
            .get("realm")
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        RuntimeHttpRequest::https(realm, None).map_err(map_download_error)?;
        let scope = parameters
            .get("scope")
            .cloned()
            .unwrap_or_else(|| format!("repository:{repository}:pull"));
        let mut query = Vec::new();
        if let Some(service) = parameters.get("service") {
            query.push(format!("service={}", percent_encode(service)));
        }
        query.push(format!("scope={}", percent_encode(&scope)));
        let separator = if realm.contains('?') { '&' } else { '?' };
        let url = format!("{realm}{separator}{}", query.join("&"));
        let response = self
            .http
            .get(
                &RuntimeHttpRequest::https(&url, Some("application/json".to_string()))
                    .map_err(map_download_error)?,
                MAX_TOKEN_BYTES,
            )
            .map_err(map_download_error)?;
        if response.status() != 200 {
            return Err(RuntimeError::RuntimePackAcquisitionUnavailable);
        }
        let value = parse_closed_json(response.body())
            .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
        let token = value
            .as_object()
            .and_then(|object| object.get("token").or_else(|| object.get("access_token")))
            .and_then(Value::as_str)
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        RuntimeBearerToken::new(token).map_err(map_download_error)
    }
}

impl RuntimePackArtifactFetcher for OciRuntimePackFetcher {
    // Acquires one exact OCI runtime pack into an empty private destination.
    fn fetch(
        &self,
        source: &RuntimeSource,
        digest: &Sha256Digest,
        destination: &Path,
    ) -> Result<(), RuntimeError> {
        self.acquire(source, digest, destination)
    }
}

// Stores one parsed immutable OCI reference.
struct OciReference {
    registry: String,
    repository: String,
    manifest_digest: Sha256Digest,
    allow_loopback_http: bool,
}

impl OciReference {
    // Parses one digest-pinned registry path without accepting mutable tags.
    fn parse(source: &RuntimeSource) -> Result<Self, RuntimeError> {
        let (name, digest) = source
            .as_str()
            .rsplit_once("@sha256:")
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        let (registry, repository) = name
            .split_once('/')
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        let registry_host = registry.split(':').next().unwrap_or_default();
        if registry.is_empty()
            || repository.is_empty()
            || registry.len() > 255
            || repository.len() > 1024
            || !is_registry(registry)
            || repository.split('/').any(|component| {
                component.is_empty()
                    || matches!(component, "." | "..")
                    || !component.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        Ok(Self {
            registry: registry.to_string(),
            repository: repository.to_string(),
            manifest_digest: Sha256Digest::parse(digest)
                .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?,
            allow_loopback_http: matches!(registry_host, "127.0.0.1" | "localhost"),
        })
    }

    // Returns the exact digest-addressed manifest URL.
    fn manifest_url(&self) -> String {
        format!(
            "{}://{}/v2/{}/manifests/sha256:{}",
            self.scheme(),
            self.registry,
            self.repository,
            self.manifest_digest.as_str()
        )
    }

    // Returns the exact digest-addressed blob URL.
    fn blob_url(&self, digest: &Sha256Digest) -> String {
        format!(
            "{}://{}/v2/{}/blobs/sha256:{}",
            self.scheme(),
            self.registry,
            self.repository,
            digest.as_str()
        )
    }

    // Returns HTTPS except for explicitly local development registries.
    const fn scheme(&self) -> &'static str {
        if self.allow_loopback_http {
            "http"
        } else {
            "https"
        }
    }
}

// Stores the one bounded runtime-pack layer declared by an OCI manifest.
struct OciLayer {
    media_type: String,
    digest: Sha256Digest,
    bytes: u64,
}

// Parses one exact schema-2 single-layer runtime artifact manifest.
fn parse_manifest(bytes: &[u8]) -> Result<OciLayer, RuntimeError> {
    let value =
        parse_closed_json(bytes).map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
    let value = value
        .as_object()
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(2)
        || !matches!(
            value.get("mediaType").and_then(Value::as_str),
            Some(OCI_IMAGE_MANIFEST | OCI_ARTIFACT_MANIFEST | DOCKER_IMAGE_MANIFEST)
        )
    {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let layers = value
        .get("layers")
        .and_then(Value::as_array)
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    if layers.len() != 1 {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let layer = layers[0]
        .as_object()
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    let media_type = layer
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    let title = layer
        .get("annotations")
        .and_then(Value::as_object)
        .and_then(|annotations| annotations.get("org.opencontainers.image.title"))
        .and_then(Value::as_str);
    if media_type != PACK_MEDIA_TYPE && title != Some("runtime.letsinfer") {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let digest = layer
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    let bytes = layer
        .get("size")
        .and_then(Value::as_u64)
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    if bytes == 0 || bytes > MAX_PACK_BYTES {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    Ok(OciLayer {
        media_type: media_type.to_string(),
        digest: Sha256Digest::parse(digest)
            .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?,
        bytes,
    })
}

// Parses one bounded Bearer challenge without accepting ambiguous parameters.
fn parse_bearer_challenge(value: Option<&str>) -> Result<BTreeMap<String, String>, RuntimeError> {
    let value = value.ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    if value.len() < 7 || !value[..7].eq_ignore_ascii_case("bearer ") {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let value = &value[7..];
    let mut parameters = BTreeMap::new();
    let bytes = value.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        while index < bytes.len() && matches!(bytes[index], b' ' | b',') {
            index += 1;
        }
        let key_start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-'))
        {
            index += 1;
        }
        if key_start == index || bytes.get(index) != Some(&b'=') {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        let key = value[key_start..index].to_ascii_lowercase();
        index += 1;
        let parsed = if bytes.get(index) == Some(&b'"') {
            index += 1;
            let mut parsed = String::new();
            let mut closed = false;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => {
                        index += 1;
                        closed = true;
                        break;
                    }
                    b'\\' => {
                        index += 1;
                        let escaped = *bytes
                            .get(index)
                            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
                        parsed.push(escaped as char);
                        index += 1;
                    }
                    byte if byte.is_ascii_control() => {
                        return Err(RuntimeError::RuntimePackAcquisitionInvalid)
                    }
                    byte => {
                        parsed.push(byte as char);
                        index += 1;
                    }
                }
            }
            if !closed {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
            parsed
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b',' {
                index += 1;
            }
            value[start..index].trim().to_string()
        };
        if parsed.is_empty() || parameters.insert(key, parsed).is_some() {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
    }
    if !parameters.contains_key("realm") {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    Ok(parameters)
}

// Resolves one absolute or relative redirect and revalidates its transport boundary.
fn resolve_redirect(
    base: &str,
    location: &str,
    allow_loopback_http: bool,
) -> Result<String, RuntimeError> {
    let resolved = if location.starts_with("https://") || location.starts_with("http://") {
        location.to_string()
    } else {
        let (scheme, remainder) = base
            .split_once("://")
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        let (authority, path) = remainder.split_once('/').unwrap_or((remainder, ""));
        if location.starts_with('/') {
            format!("{scheme}://{authority}{location}")
        } else {
            let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            format!(
                "{scheme}://{authority}/{}{}{}",
                parent,
                if parent.is_empty() { "" } else { "/" },
                location
            )
        }
    };
    RuntimeHttpRequest::new(&resolved, None, None, allow_loopback_http, 60)
        .map_err(map_download_error)?;
    Ok(resolved)
}

// Returns whether one registry uses a bounded hostname and optional numeric TCP port.
fn is_registry(value: &str) -> bool {
    let mut parts = value.split(':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next();
    if parts.next().is_some()
        || host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return false;
    }
    port.is_none_or(|value| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u16>().ok().is_some_and(|port| port != 0)
    })
}

// Percent-encodes one URL query value using the RFC-3986 unreserved alphabet.
fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

// Maps HTTP failures into the runtime-pack boundary without exposing URLs or tokens.
fn map_download_error(error: RuntimeError) -> RuntimeError {
    match error {
        RuntimeError::DownloadUnavailable => RuntimeError::RuntimePackAcquisitionUnavailable,
        _ => RuntimeError::RuntimePackAcquisitionInvalid,
    }
}

// Verifies one complete runtime artifact descriptor and closed file inventory.
fn verified_runtime_documents(destination: &Path) -> Result<RuntimePackDocuments, RuntimeError> {
    validate_private_directory(destination)?;
    let descriptor_path = destination.join(RUNTIME_DESCRIPTOR);
    let descriptor_bytes = read_bounded(&descriptor_path, 16 * 1024 * 1024)?;
    let descriptor = parse_closed_json(&descriptor_bytes)
        .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
    let descriptor_object = descriptor
        .as_object()
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    exact_fields(
        descriptor_object,
        &[
            "artifact_schema_version",
            "media_type",
            "runtime_sha256",
            "candidate",
            "files",
        ],
    )?;
    let descriptor_digest = canonical_sha256(&descriptor)?;
    if descriptor_object
        .get("artifact_schema_version")
        .and_then(Value::as_u64)
        != Some(6)
        || descriptor_object.get("media_type").and_then(Value::as_str) != Some(PACK_MEDIA_TYPE)
    {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let runtime_sha256 = parse_digest(
        descriptor_object
            .get("runtime_sha256")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?,
    )?;
    let files = descriptor_object
        .get("files")
        .and_then(Value::as_array)
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    if files.is_empty() || files.len() > MAX_PACK_FILES {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let mut expected = HashSet::new();
    let mut total = 0_u64;
    for value in files {
        let record = value
            .as_object()
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        exact_fields(record, &["path", "bytes", "mode", "sha256"])?;
        let relative = safe_relative(Path::new(
            record
                .get("path")
                .and_then(Value::as_str)
                .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?,
        ))?;
        if relative == Path::new(RUNTIME_DESCRIPTOR) || !expected.insert(relative.clone()) {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        let bytes = record
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        let mode = record
            .get("mode")
            .and_then(Value::as_u64)
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)? as u32;
        let digest = parse_digest(
            record
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?,
        )?;
        if !matches!(mode, 0o644 | 0o755) {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        total = total
            .checked_add(bytes)
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
        if total > MAX_PACK_BYTES {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        verify_file(&destination.join(&relative), bytes, mode, &digest)?;
    }
    if !expected.contains(Path::new(RUNTIME_CONFIG)) {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let actual = source_files(destination)?;
    if actual != expected {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let runtime_bytes = read_bounded(&destination.join(RUNTIME_CONFIG), 16 * 1024 * 1024)?;
    if sha256(&runtime_bytes) != runtime_sha256 {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    validate_candidate_summary(
        descriptor_object
            .get("candidate")
            .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?,
        &runtime_bytes,
    )?;
    Ok(RuntimePackDocuments::from_verified(
        descriptor_digest,
        descriptor_bytes,
        runtime_bytes,
    ))
}

// Requires descriptor candidate summary to equal exact runtime.json identities.
fn validate_candidate_summary(candidate: &Value, runtime_bytes: &[u8]) -> Result<(), RuntimeError> {
    let candidate = candidate
        .as_object()
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    exact_fields(
        candidate,
        &["id", "version", "logical_model", "engine", "target"],
    )?;
    let runtime = parse_closed_json(runtime_bytes)
        .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
    let runtime = runtime
        .as_object()
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    let engine = runtime
        .get("engine")
        .and_then(Value::as_object)
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    let target = runtime
        .get("target")
        .and_then(Value::as_object)
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .ok_or(RuntimeError::RuntimePackAcquisitionInvalid)?;
    for (field, expected) in [
        ("id", runtime.get("id").and_then(Value::as_str)),
        ("version", runtime.get("version").and_then(Value::as_str)),
        (
            "logical_model",
            runtime.get("logical_model").and_then(Value::as_str),
        ),
        ("engine", Some(engine)),
        ("target", Some(target)),
    ] {
        if candidate.get(field).and_then(Value::as_str) != expected || expected.is_none() {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
    }
    Ok(())
}

// Returns every regular source file except the descriptor itself.
fn source_files(root: &Path) -> Result<HashSet<PathBuf>, RuntimeError> {
    let mut result = HashSet::new();
    collect_source_files(root, root, &mut result)?;
    result.remove(Path::new(RUNTIME_DESCRIPTOR));
    Ok(result)
}

// Recursively collects a bounded no-follow regular file inventory.
fn collect_source_files(
    root: &Path,
    current: &Path,
    result: &mut HashSet<PathBuf>,
) -> Result<(), RuntimeError> {
    for entry in current
        .read_dir()
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?
    {
        let entry = entry.map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        if metadata.is_dir() {
            collect_source_files(root, &path, result)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?
                .to_path_buf();
            if !result.insert(relative) || result.len() > MAX_PACK_FILES + 1 {
                return Err(RuntimeError::RuntimePackAcquisitionInvalid);
            }
        } else {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
    }
    Ok(())
}

// Verifies one exact regular file identity and Unix mode.
fn verify_file(
    path: &Path,
    expected_bytes: u64,
    expected_mode: u32,
    expected_digest: &Sha256Digest,
) -> Result<(), RuntimeError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != expected_mode {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if sha256_digest(digest.finalize().as_slice()) != *expected_digest {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    Ok(())
}

// Reads one bounded no-follow regular file.
fn read_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut file = open_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
    if !metadata.is_file() || metadata.len() > maximum_bytes as u64 {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    Ok(bytes)
}

// Requires one exact JSON object field set.
fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), RuntimeError> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    Ok(())
}

// Parses one canonical lowercase SHA-256.
fn parse_digest(value: &str) -> Result<Sha256Digest, RuntimeError> {
    Sha256Digest::parse(value).map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)
}

// Returns the canonical JSON SHA-256 with the shared trailing-newline contract.
fn canonical_sha256(value: &Value) -> Result<Sha256Digest, RuntimeError> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| RuntimeError::RuntimePackAcquisitionInvalid)?;
    bytes.push(b'\n');
    Ok(sha256(&bytes))
}

// Returns the exact SHA-256 identity of one byte sequence.
fn sha256(bytes: &[u8]) -> Sha256Digest {
    sha256_digest(Sha256::digest(bytes).as_slice())
}

// Converts finalized SHA-256 bytes into the shared identity type.
fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(
        &bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("SHA-256 encoder produces one canonical digest")
}

// Parses one contained relative path without platform-dependent normalization.
fn safe_relative(path: &Path) -> Result<PathBuf, RuntimeError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    Ok(path.to_path_buf())
}

// Creates one private relative parent chain without following existing links.
fn create_private_parents(root: &Path, relative: &Path) -> Result<(), RuntimeError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        };
        current.push(component);
        if current.exists() || current.is_symlink() {
            validate_private_directory(&current)?;
        } else {
            fs::create_dir(&current)
                .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
            set_mode(&current, 0o700)?;
        }
    }
    Ok(())
}

// Requires one no-follow owner-only directory.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::RuntimePackAcquisitionInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
    }
    Ok(())
}

// Removes every safe contained entry from one private directory.
fn clear_directory(path: &Path) -> Result<(), RuntimeError> {
    let entries = path
        .read_dir()
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
        if metadata.is_dir() {
            clear_directory(&path)?;
            fs::remove_dir(&path).map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        } else if metadata.is_file() {
            fs::remove_file(&path).map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)?;
        } else {
            return Err(RuntimeError::RuntimePackAcquisitionInvalid);
        }
    }
    Ok(())
}

// Creates one no-follow regular file with an exact mode.
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
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)
}

// Opens one regular file without following the final path.
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
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)
}

// Sets one exact owner-controlled Unix mode.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| RuntimeError::RuntimePackAcquisitionUnavailable)
}

// Leaves modes to the future Windows provider.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), RuntimeError> {
    Ok(())
}
