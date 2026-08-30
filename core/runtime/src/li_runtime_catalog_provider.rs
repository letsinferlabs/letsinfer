// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use li_core_interface::{
    ArtifactRevision, CpuArchitecture, EngineDistribution, EvidenceLabel, HardwareObservation,
    LogicalModelName, MemoryTopology, NativeEngineKind, OperatingSystem, RuntimeCandidateId,
    RuntimeSource, Sha256Digest, TargetId, TechnicalName,
};
use ring::signature;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    RuntimeAcceleratorPartitioning, RuntimeAcceleratorVendor, RuntimeCandidate,
    RuntimeCatalogProvider, RuntimeError, RuntimeHttpClient, RuntimeHttpRequest, RuntimeTarget,
};

use super::li_runtime_catalog_schema::{
    apply_revocations, catalog_compute_matches, catalog_vendor_matches, gibibytes, is_https_url,
    is_lower_hex, object, parse_catalog, parse_closed_json, parse_revocations,
    platform_identity_name, platform_name, require_fields, string, unsigned, ActiveCatalog,
};

const CACHE_SCHEMA_VERSION: u64 = 3;
pub(crate) const CATALOG_SCHEMA_VERSION: u64 = 7;
const DEFAULT_MAXIMUM_AGE_SECONDS: u64 = 60 * 60;
const ENGINE_PROTOCOL_VERSION: u16 = 2;
pub(crate) const MAXIMUM_CATALOG_BYTES: u64 = 4 << 20;
pub(crate) const MAXIMUM_LEDGER_BYTES: u64 = 1 << 20;
const MAXIMUM_SIGNATURE_BYTES: u64 = 16 << 10;
pub(crate) const RECOMMENDATION_POLICY: &str = "letsinfer-throughput-geomean-v1";
pub(crate) const RECOMMENDATION_SUITE: &str = "letsinfer-code-prose-v1";
const TRUSTED_PUBLIC_KEY: [u8; 32] = [
    0x39, 0x02, 0x5c, 0xef, 0xa9, 0x4e, 0x5b, 0x0c, 0x8f, 0xd6, 0x7c, 0x71, 0x82, 0xd6, 0x89, 0x0c,
    0x45, 0x39, 0x2d, 0xe5, 0xf9, 0xe9, 0x01, 0x6c, 0xe9, 0xbc, 0x7d, 0x59, 0xfb, 0x6d, 0x12, 0x11,
];

// Identifies the signed document whose detached envelope is being verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCatalogSignatureKind {
    Catalog,
    Revocations,
}

// Carries one exact trusted Ed25519 public key and its DER-bound identity.
#[derive(Clone)]
pub struct RuntimeCatalogTrustRoot {
    public_key: [u8; 32],
    key_id: Sha256Digest,
}

impl RuntimeCatalogTrustRoot {
    // Creates one trust root only when its key identity matches the standard DER encoding.
    pub fn new(public_key: [u8; 32], key_id: Sha256Digest) -> Result<Self, RuntimeError> {
        if sha256_digest(&ed25519_public_key_der(&public_key)) != key_id {
            return Err(RuntimeError::CatalogTrustUnavailable);
        }
        Ok(Self { public_key, key_id })
    }

    // Returns the raw Ed25519 verification key.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    // Returns the DER-bound trusted key identity.
    pub const fn key_id(&self) -> &Sha256Digest {
        &self.key_id
    }
}

// Supplies the immutable catalog trust root without exposing signing material.
pub trait RuntimeCatalogTrustProvider: Send + Sync {
    // Returns the exact trusted public key for one catalog load.
    fn trust_root(&self) -> Result<RuntimeCatalogTrustRoot, RuntimeError>;
}

// Supplies one explicitly constructed immutable catalog trust root.
pub struct StaticRuntimeCatalogTrustProvider {
    root: RuntimeCatalogTrustRoot,
}

impl StaticRuntimeCatalogTrustProvider {
    // Creates one provider from an already validated trust root.
    pub const fn new(root: RuntimeCatalogTrustRoot) -> Self {
        Self { root }
    }

    // Creates the production provider from the Core-owned catalog key.
    pub fn letsinfer() -> Result<Self, RuntimeError> {
        let key_id = sha256_digest(&ed25519_public_key_der(&TRUSTED_PUBLIC_KEY));
        Ok(Self::new(RuntimeCatalogTrustRoot::new(
            TRUSTED_PUBLIC_KEY,
            key_id,
        )?))
    }
}

impl RuntimeCatalogTrustProvider for StaticRuntimeCatalogTrustProvider {
    // Returns a copy of the immutable trust root.
    fn trust_root(&self) -> Result<RuntimeCatalogTrustRoot, RuntimeError> {
        Ok(self.root.clone())
    }
}

// Verifies one detached signed-document envelope against an injected trust root.
pub trait RuntimeCatalogSignatureVerifier: Send + Sync {
    // Verifies exact document bytes before any catalog or ledger parsing occurs.
    fn verify(
        &self,
        kind: RuntimeCatalogSignatureKind,
        document: &[u8],
        signature: &[u8],
        trust: &RuntimeCatalogTrustRoot,
    ) -> Result<(), RuntimeError>;
}

// Verifies the production Ed25519 envelope without invoking a native process.
pub struct Ed25519RuntimeCatalogSignatureVerifier;

impl RuntimeCatalogSignatureVerifier for Ed25519RuntimeCatalogSignatureVerifier {
    // Verifies envelope identity, trusted key identity, and the exact Ed25519 signature.
    fn verify(
        &self,
        kind: RuntimeCatalogSignatureKind,
        document: &[u8],
        signature_bytes: &[u8],
        trust: &RuntimeCatalogTrustRoot,
    ) -> Result<(), RuntimeError> {
        if signature_bytes.len() > MAXIMUM_SIGNATURE_BYTES as usize {
            return Err(RuntimeError::CatalogSignatureInvalid);
        }
        let value = parse_closed_json(signature_bytes)
            .map_err(|_| RuntimeError::CatalogSignatureInvalid)?;
        let object = object(&value).map_err(|_| RuntimeError::CatalogSignatureInvalid)?;
        let expected_fields: &[&str] = match kind {
            RuntimeCatalogSignatureKind::Catalog => &[
                "algorithm",
                "catalog_sha256",
                "key_id_sha256",
                "schema_version",
                "signature_base64",
            ],
            RuntimeCatalogSignatureKind::Revocations => &[
                "algorithm",
                "document_kind",
                "document_sha256",
                "key_id_sha256",
                "schema_version",
                "signature_base64",
            ],
        };
        require_fields(object, expected_fields)
            .map_err(|_| RuntimeError::CatalogSignatureInvalid)?;
        if unsigned(object, "schema_version").ok() != Some(1)
            || string(object, "algorithm").ok() != Some("ed25519")
            || string(object, "key_id_sha256").ok() != Some(trust.key_id().as_str())
        {
            return Err(RuntimeError::CatalogSignatureInvalid);
        }
        let document_digest = sha256_digest(document);
        match kind {
            RuntimeCatalogSignatureKind::Catalog => {
                if string(object, "catalog_sha256").ok() != Some(document_digest.as_str()) {
                    return Err(RuntimeError::CatalogSignatureInvalid);
                }
            }
            RuntimeCatalogSignatureKind::Revocations => {
                if string(object, "document_kind").ok() != Some("letsinfer.revocations")
                    || string(object, "document_sha256").ok() != Some(document_digest.as_str())
                {
                    return Err(RuntimeError::CatalogSignatureInvalid);
                }
            }
        }
        let encoded = string(object, "signature_base64")
            .map_err(|_| RuntimeError::CatalogSignatureInvalid)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| RuntimeError::CatalogSignatureInvalid)?;
        if raw.len() != 64 {
            return Err(RuntimeError::CatalogSignatureInvalid);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, trust.public_key())
            .verify(document, &raw)
            .map_err(|_| RuntimeError::CatalogSignatureInvalid)
    }
}

// Supplies a deterministic wall clock for freshness decisions.
pub trait RuntimeCatalogClock: Send + Sync {
    // Returns the current Unix timestamp in whole seconds.
    fn now_unix(&self) -> Result<u64, RuntimeError>;
}

// Reads the production wall clock without retaining mutable state.
pub struct SystemRuntimeCatalogClock;

impl RuntimeCatalogClock for SystemRuntimeCatalogClock {
    // Returns the current non-negative Unix timestamp.
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| RuntimeError::CatalogUnavailable)
    }
}

// Stores the exact signed bytes and source identity of one verified snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogCacheEntry {
    source: String,
    catalog: Vec<u8>,
    catalog_signature: Vec<u8>,
    revocations: Vec<u8>,
    revocations_signature: Vec<u8>,
    verified_at_unix: u64,
}

impl RuntimeCatalogCacheEntry {
    // Creates one bounded cache entry from exact downloaded bytes.
    pub fn new(
        source: String,
        catalog: Vec<u8>,
        catalog_signature: Vec<u8>,
        revocations: Vec<u8>,
        revocations_signature: Vec<u8>,
        verified_at_unix: u64,
    ) -> Result<Self, RuntimeError> {
        if !is_https_url(&source)
            || catalog.is_empty()
            || catalog.len() > MAXIMUM_CATALOG_BYTES as usize
            || catalog_signature.is_empty()
            || catalog_signature.len() > MAXIMUM_SIGNATURE_BYTES as usize
            || revocations.is_empty()
            || revocations.len() > MAXIMUM_LEDGER_BYTES as usize
            || revocations_signature.is_empty()
            || revocations_signature.len() > MAXIMUM_SIGNATURE_BYTES as usize
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(Self {
            source,
            catalog,
            catalog_signature,
            revocations,
            revocations_signature,
            verified_at_unix,
        })
    }

    // Returns the exact catalog source URL.
    pub fn source(&self) -> &str {
        &self.source
    }

    // Returns the exact signed catalog bytes.
    pub fn catalog(&self) -> &[u8] {
        &self.catalog
    }

    // Returns the exact catalog signature envelope.
    pub fn catalog_signature(&self) -> &[u8] {
        &self.catalog_signature
    }

    // Returns the exact signed revocation-ledger bytes.
    pub fn revocations(&self) -> &[u8] {
        &self.revocations
    }

    // Returns the exact revocation signature envelope.
    pub fn revocations_signature(&self) -> &[u8] {
        &self.revocations_signature
    }

    // Returns when the complete snapshot was verified.
    pub const fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    // Returns the identity binding both exact signed documents.
    pub fn snapshot_sha256(&self) -> Sha256Digest {
        snapshot_digest(&self.catalog, &self.revocations)
    }
}

// Persists and reconstructs the last complete verified catalog snapshot.
pub trait RuntimeCatalogCache: Send + Sync {
    // Reads the current exact snapshot when one exists.
    fn read(&self) -> Result<Option<RuntimeCatalogCacheEntry>, RuntimeError>;

    // Atomically publishes one complete verified snapshot.
    fn write(&self, entry: &RuntimeCatalogCacheEntry) -> Result<(), RuntimeError>;

    // Reads the independent monotonic revocation anchor for one catalog source.
    fn read_revocation_anchor(
        &self,
        source: &str,
    ) -> Result<Option<RuntimeCatalogRevocationAnchor>, RuntimeError>;

    // Advances one source anchor without permitting rollback or equivocation.
    fn write_revocation_anchor(
        &self,
        anchor: &RuntimeCatalogRevocationAnchor,
    ) -> Result<(), RuntimeError>;
}

// Persists the highest verified revocation sequence independently of cache selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogRevocationAnchor {
    source: String,
    sequence: u64,
    revocations_sha256: Sha256Digest,
}

impl RuntimeCatalogRevocationAnchor {
    // Creates one source-bound anchor from an already verified revocation document.
    pub fn new(
        source: String,
        sequence: u64,
        revocations_sha256: Sha256Digest,
    ) -> Result<Self, RuntimeError> {
        if !is_https_url(&source) || !source.ends_with("/catalog.json") {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(Self {
            source,
            sequence,
            revocations_sha256,
        })
    }

    // Returns the exact catalog source protected by this anchor.
    pub fn source(&self) -> &str {
        &self.source
    }

    // Returns the highest verified revocation sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    // Returns the exact signed revocation document identity at that sequence.
    pub const fn revocations_sha256(&self) -> &Sha256Digest {
        &self.revocations_sha256
    }
}

// Persists immutable catalog objects beneath one private Core-owned directory.
pub struct FilesystemRuntimeCatalogCache {
    root: PathBuf,
}

impl FilesystemRuntimeCatalogCache {
    // Creates one filesystem cache from an explicit absolute state directory.
    pub fn new(root: PathBuf) -> Result<Self, RuntimeError> {
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(Self { root })
    }

    // Returns the immutable object directory.
    fn objects(&self) -> PathBuf {
        self.root.join("objects")
    }

    // Returns the independent source-keyed revocation-anchor directory.
    fn anchors(&self) -> PathBuf {
        self.root.join("revocation-anchors")
    }

    // Returns one contained anchor path derived only from the source digest.
    fn anchor(&self, source: &str) -> PathBuf {
        self.anchors().join(format!(
            "{}.json",
            sha256_digest(source.as_bytes()).as_str()
        ))
    }

    // Returns one contained lock path for serializing a source anchor across processes.
    fn anchor_lock(&self, source: &str) -> PathBuf {
        self.anchors().join(format!(
            ".{}.lock",
            sha256_digest(source.as_bytes()).as_str()
        ))
    }

    // Returns the atomic current-snapshot pointer.
    fn current(&self) -> PathBuf {
        self.root.join("current.json")
    }

    // Creates and validates the private cache hierarchy.
    fn prepare(&self) -> Result<(), RuntimeError> {
        create_private_directory(&self.root)?;
        create_private_directory(&self.objects())?;
        create_private_directory(&self.anchors())
    }

    // Reads and validates one exact source-bound monotonic anchor document.
    fn read_anchor(
        &self,
        source: &str,
    ) -> Result<Option<RuntimeCatalogRevocationAnchor>, RuntimeError> {
        if !is_https_url(source) || !source.ends_with("/catalog.json") {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        if !self.root.exists() {
            return Ok(None);
        }
        self.prepare()?;
        let path = self.anchor(source);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_private_file(&path, 16 << 10)?;
        let value = parse_closed_json(&bytes).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        let value = object(&value).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        require_fields(
            value,
            &["revocations_sha256", "schema_version", "sequence", "source"],
        )
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        if unsigned(value, "schema_version").ok() != Some(1)
            || string(value, "source").ok() != Some(source)
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        RuntimeCatalogRevocationAnchor::new(
            source.to_string(),
            unsigned(value, "sequence").map_err(|_| RuntimeError::CatalogCacheUnavailable)?,
            Sha256Digest::parse(
                string(value, "revocations_sha256")
                    .map_err(|_| RuntimeError::CatalogCacheUnavailable)?,
            )
            .map_err(|_| RuntimeError::CatalogCacheUnavailable)?,
        )
        .map(Some)
    }

    // Atomically advances one source anchor after enforcing monotonic identity.
    fn write_anchor(&self, anchor: &RuntimeCatalogRevocationAnchor) -> Result<(), RuntimeError> {
        self.prepare()?;
        let _lock = RuntimeCatalogAnchorLock::acquire(&self.anchor_lock(anchor.source()))?;
        if let Some(existing) = self.read_anchor(anchor.source())? {
            if anchor.sequence() < existing.sequence()
                || (anchor.sequence() == existing.sequence()
                    && anchor.revocations_sha256() != existing.revocations_sha256())
            {
                return Err(RuntimeError::CatalogInvalid);
            }
            if anchor == &existing {
                return Ok(());
            }
        }
        let temporary = self
            .anchors()
            .join(format!(".anchor-{}", random_identity()?));
        let bytes = canonical_json_bytes(&serde_json::json!({
            "schema_version": 1,
            "source": anchor.source(),
            "sequence": anchor.sequence(),
            "revocations_sha256": anchor.revocations_sha256().as_str(),
        }))?;
        write_private_file(&temporary, &bytes)?;
        let result = fs::rename(&temporary, self.anchor(anchor.source()))
            .and_then(|()| File::open(self.anchors()).and_then(|directory| directory.sync_all()))
            .map_err(|_| RuntimeError::CatalogCacheUnavailable);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    // Reads one immutable cache object after checking its complete identity.
    fn read_object(
        &self,
        identity: &str,
        source: &str,
        verified_at_unix: u64,
    ) -> Result<RuntimeCatalogCacheEntry, RuntimeError> {
        if !is_lower_hex(identity, 64) {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        let root = self.objects().join(identity);
        validate_private_directory(&root)?;
        let catalog = read_private_file(&root.join("catalog.json"), MAXIMUM_CATALOG_BYTES)?;
        let catalog_signature =
            read_private_file(&root.join("catalog.json.sig"), MAXIMUM_SIGNATURE_BYTES)?;
        let revocations = read_private_file(&root.join("revocations.json"), MAXIMUM_LEDGER_BYTES)?;
        let revocations_signature =
            read_private_file(&root.join("revocations.json.sig"), MAXIMUM_SIGNATURE_BYTES)?;
        let metadata_bytes = read_private_file(&root.join("metadata.json"), 16 << 10)?;
        let metadata = parse_closed_json(&metadata_bytes)
            .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        let metadata = object(&metadata).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        require_fields(
            metadata,
            &[
                "catalog_sha256",
                "revocations_sha256",
                "schema_version",
                "snapshot_sha256",
            ],
        )
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        let entry = RuntimeCatalogCacheEntry::new(
            source.to_string(),
            catalog,
            catalog_signature,
            revocations,
            revocations_signature,
            verified_at_unix,
        )?;
        if unsigned(metadata, "schema_version").ok() != Some(CACHE_SCHEMA_VERSION)
            || string(metadata, "snapshot_sha256").ok() != Some(identity)
            || string(metadata, "catalog_sha256").ok()
                != Some(sha256_digest(entry.catalog()).as_str())
            || string(metadata, "revocations_sha256").ok()
                != Some(sha256_digest(entry.revocations()).as_str())
            || entry.snapshot_sha256().as_str() != identity
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(entry)
    }

    // Writes one complete new immutable cache object.
    fn write_object(&self, entry: &RuntimeCatalogCacheEntry) -> Result<String, RuntimeError> {
        let identity = entry.snapshot_sha256().as_str().to_string();
        let destination = self.objects().join(&identity);
        if destination.exists() {
            let existing = self.read_object(&identity, entry.source(), entry.verified_at_unix())?;
            if existing.catalog() != entry.catalog()
                || existing.catalog_signature() != entry.catalog_signature()
                || existing.revocations() != entry.revocations()
                || existing.revocations_signature() != entry.revocations_signature()
            {
                return Err(RuntimeError::CatalogCacheUnavailable);
            }
            return Ok(identity);
        }
        let temporary = self
            .objects()
            .join(format!(".incoming-{}", random_identity()?));
        create_new_private_directory(&temporary)?;
        let result = (|| {
            write_private_file(&temporary.join("catalog.json"), entry.catalog())?;
            write_private_file(
                &temporary.join("catalog.json.sig"),
                entry.catalog_signature(),
            )?;
            write_private_file(&temporary.join("revocations.json"), entry.revocations())?;
            write_private_file(
                &temporary.join("revocations.json.sig"),
                entry.revocations_signature(),
            )?;
            let metadata = canonical_json_bytes(&serde_json::json!({
                "schema_version": CACHE_SCHEMA_VERSION,
                "snapshot_sha256": identity,
                "catalog_sha256": sha256_digest(entry.catalog()).as_str(),
                "revocations_sha256": sha256_digest(entry.revocations()).as_str(),
            }))?;
            write_private_file(&temporary.join("metadata.json"), &metadata)?;
            fs::rename(&temporary, &destination)
                .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
            Ok(())
        })();
        if result.is_err() && temporary.exists() && !temporary.is_symlink() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result.map(|()| identity)
    }

    // Atomically publishes the current immutable object identity.
    fn write_current(
        &self,
        identity: &str,
        entry: &RuntimeCatalogCacheEntry,
    ) -> Result<(), RuntimeError> {
        let temporary = self.root.join(format!(".current-{}", random_identity()?));
        let pointer = canonical_json_bytes(&serde_json::json!({
            "schema_version": CACHE_SCHEMA_VERSION,
            "snapshot_sha256": identity,
            "source": entry.source(),
            "verified_at_unix": entry.verified_at_unix(),
        }))?;
        write_private_file(&temporary, &pointer)?;
        let result = fs::rename(&temporary, self.current())
            .map_err(|_| RuntimeError::CatalogCacheUnavailable);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

// Holds one owner-only advisory lock across a monotonic anchor compare-and-replace.
struct RuntimeCatalogAnchorLock(File);

impl RuntimeCatalogAnchorLock {
    // Opens one no-follow lock file and acquires an exclusive cross-process advisory lock.
    fn acquire(path: &Path) -> Result<Self, RuntimeError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(path)
            .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        // SAFETY: the verified file remains open for the complete lock lifetime.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        Ok(Self(file))
    }
}

impl Drop for RuntimeCatalogAnchorLock {
    // Releases only this open file description's advisory lock.
    fn drop(&mut self) {
        // SAFETY: the file descriptor remains valid until after Drop returns.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl RuntimeCatalogCache for FilesystemRuntimeCatalogCache {
    // Reconstructs the exact current immutable cache object.
    fn read(&self) -> Result<Option<RuntimeCatalogCacheEntry>, RuntimeError> {
        if !self.current().exists() {
            return Ok(None);
        }
        self.prepare()?;
        let pointer_bytes = read_private_file(&self.current(), 16 << 10)?;
        let pointer =
            parse_closed_json(&pointer_bytes).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        let pointer = object(&pointer).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        require_fields(
            pointer,
            &[
                "schema_version",
                "snapshot_sha256",
                "source",
                "verified_at_unix",
            ],
        )
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        if unsigned(pointer, "schema_version").ok() != Some(CACHE_SCHEMA_VERSION) {
            return Err(RuntimeError::CatalogCacheUnavailable);
        }
        self.read_object(
            string(pointer, "snapshot_sha256")
                .map_err(|_| RuntimeError::CatalogCacheUnavailable)?,
            string(pointer, "source").map_err(|_| RuntimeError::CatalogCacheUnavailable)?,
            unsigned(pointer, "verified_at_unix")
                .map_err(|_| RuntimeError::CatalogCacheUnavailable)?,
        )
        .map(Some)
    }

    // Publishes one exact entry without overwriting immutable object bytes.
    fn write(&self, entry: &RuntimeCatalogCacheEntry) -> Result<(), RuntimeError> {
        self.prepare()?;
        let identity = self.write_object(entry)?;
        self.write_current(&identity, entry)
    }

    // Reads one source-keyed monotonic revocation anchor independently of current selection.
    fn read_revocation_anchor(
        &self,
        source: &str,
    ) -> Result<Option<RuntimeCatalogRevocationAnchor>, RuntimeError> {
        self.read_anchor(source)
    }

    // Atomically advances one source-keyed monotonic revocation anchor.
    fn write_revocation_anchor(
        &self,
        anchor: &RuntimeCatalogRevocationAnchor,
    ) -> Result<(), RuntimeError> {
        self.write_anchor(anchor)
    }
}

// Identifies one structured author account without collapsing its order or account kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCatalogAuthorKind {
    User,
    Organization,
}

// Preserves one ordered structured runtime author identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogAuthor {
    pub(crate) github_login: String,
    pub(crate) github_id: u64,
    pub(crate) github_type: RuntimeCatalogAuthorKind,
}

impl RuntimeCatalogAuthor {
    // Returns the authored GitHub login exactly as published.
    pub fn github_login(&self) -> &str {
        &self.github_login
    }

    // Returns the immutable numeric GitHub account identity.
    pub const fn github_id(&self) -> u64 {
        self.github_id
    }

    // Returns whether the author is a user or organization.
    pub const fn github_type(&self) -> RuntimeCatalogAuthorKind {
        self.github_type
    }
}

// Preserves the signed compact Engine distribution identity used by the catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCatalogEngineDistribution {
    Oci {
        reference: RuntimeSource,
        payload_id: Option<Sha256Digest>,
    },
    Native {
        kind: NativeEngineKind,
        platform: String,
        payload_id: Sha256Digest,
        source_revision: ArtifactRevision,
    },
}

impl RuntimeCatalogEngineDistribution {
    // Returns whether one hydrated full Engine identity preserves this signed projection.
    fn matches(&self, value: &EngineDistribution) -> bool {
        match (self, value) {
            (
                Self::Oci {
                    reference,
                    payload_id,
                },
                EngineDistribution::Oci {
                    reference: actual,
                    immutable_id,
                    payload_id: actual_payload,
                    ..
                },
            ) => {
                reference == actual
                    && reference
                        .as_str()
                        .rsplit_once("@sha256:")
                        .is_some_and(|(_, digest)| digest == immutable_id.as_str())
                    && payload_id == actual_payload
            }
            (
                Self::Native {
                    kind,
                    platform,
                    payload_id,
                    source_revision,
                },
                EngineDistribution::Native {
                    kind: actual_kind,
                    platform: actual_platform,
                    payload_id: actual_payload,
                    source_revision: actual_revision,
                },
            ) => {
                kind == actual_kind
                    && platform == &platform_identity_name(*actual_platform)
                    && payload_id == actual_payload
                    && source_revision == actual_revision
            }
            _ => false,
        }
    }
}

// Identifies the interconnect family declared by one placement target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCatalogInterconnectKind {
    Any,
    Connectx,
    Ethernet,
    Wifi,
    Other,
}

// Preserves placement requirements while leaving live allocation to PlacementManager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogPlacement {
    pub(crate) parallel: bool,
    pub(crate) node_count: u16,
    pub(crate) interconnect: RuntimeCatalogInterconnectKind,
    pub(crate) rdma_required: bool,
    pub(crate) minimum_speed_mbps: u64,
    pub(crate) minimum_mtu: u32,
}

impl RuntimeCatalogPlacement {
    // Returns whether the runtime owns a multi-node parallel execution.
    pub const fn is_parallel(&self) -> bool {
        self.parallel
    }

    // Returns the exact number of nodes consumed by one placement group.
    pub const fn node_count(&self) -> u16 {
        self.node_count
    }

    // Returns the signed interconnect family required at placement time.
    pub const fn interconnect_kind(&self) -> RuntimeCatalogInterconnectKind {
        self.interconnect
    }

    // Returns whether every selected placement link must provide RDMA.
    pub const fn requires_rdma(&self) -> bool {
        self.rdma_required
    }

    // Returns the minimum observed link speed required at placement time.
    pub const fn minimum_speed_mbps(&self) -> u64 {
        self.minimum_speed_mbps
    }

    // Returns the minimum observed link MTU required at placement time.
    pub const fn minimum_mtu(&self) -> u32 {
        self.minimum_mtu
    }
}

// Preserves one complete signed target contract and its canonical digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogTarget {
    pub(crate) id: TargetId,
    pub(crate) operating_system: String,
    pub(crate) architecture: String,
    pub(crate) accelerator_vendor: String,
    pub(crate) compute_architecture: String,
    pub(crate) accelerator_count: u64,
    pub(crate) accelerator_partitioning: RuntimeAcceleratorPartitioning,
    pub(crate) minimum_accelerator_memory_gib: Option<u64>,
    pub(crate) memory_topology: MemoryTopology,
    pub(crate) minimum_total_memory_gib: u64,
    pub(crate) placement: RuntimeCatalogPlacement,
    pub(crate) contract_sha256: Sha256Digest,
}

impl RuntimeCatalogTarget {
    // Returns the exact catalog target identity.
    pub const fn id(&self) -> &TargetId {
        &self.id
    }

    // Returns the canonical target-contract digest.
    pub const fn contract_sha256(&self) -> &Sha256Digest {
        &self.contract_sha256
    }

    // Returns placement requirements without treating mutable links as static facts.
    pub const fn placement(&self) -> &RuntimeCatalogPlacement {
        &self.placement
    }

    // Matches the same stable host capabilities as the production schema-7 matcher.
    pub fn matches(&self, hardware: &HardwareObservation) -> bool {
        if platform_name(hardware) != format!("{}/{}", self.operating_system, self.architecture)
            || self.accelerator_partitioning != RuntimeAcceleratorPartitioning::FullDevice
            || hardware.memory_bytes().value()
                < self.minimum_total_memory_gib.saturating_mul(1 << 30)
        {
            return false;
        }
        let minimum_accelerator_bytes = self
            .minimum_accelerator_memory_gib
            .map(|minimum| minimum.saturating_mul(1 << 30));
        if self.memory_topology == MemoryTopology::Unified
            && minimum_accelerator_bytes
                .is_some_and(|minimum| hardware.memory_bytes().value() < minimum)
        {
            return false;
        }
        hardware
            .accelerators()
            .iter()
            .filter(|accelerator| {
                catalog_vendor_matches(accelerator.vendor(), &self.accelerator_vendor)
                    && catalog_compute_matches(accelerator.compute(), &self.compute_architecture)
                    && accelerator.memory().topology() == self.memory_topology
                    && match self.memory_topology {
                        MemoryTopology::Discrete => {
                            minimum_accelerator_bytes.is_none_or(|minimum| {
                                accelerator
                                    .memory()
                                    .framebuffer_bytes()
                                    .is_some_and(|bytes| bytes.value() >= minimum)
                            })
                        }
                        MemoryTopology::Unified => true,
                        MemoryTopology::Unknown => false,
                    }
            })
            .count()
            >= usize::try_from(self.accelerator_count).unwrap_or(usize::MAX)
    }

    // Converts a supported Core host target into RuntimeManager's installation judgment type.
    pub(crate) fn runtime_target(&self) -> Result<RuntimeTarget, RuntimeError> {
        let operating_system = match self.operating_system.as_str() {
            "linux" => OperatingSystem::Linux,
            "macos" => OperatingSystem::Macos,
            _ => {
                return Err(RuntimeError::InvalidCandidate {
                    reason: "catalog target operating system is unsupported by Core",
                })
            }
        };
        let architecture = match self.architecture.as_str() {
            "arm64" => CpuArchitecture::Arm64,
            "x86_64" => CpuArchitecture::X86_64,
            _ => {
                return Err(RuntimeError::InvalidCandidate {
                    reason: "catalog target architecture is unsupported by Core",
                })
            }
        };
        let vendor = match self.accelerator_vendor.as_str() {
            "nvidia" => RuntimeAcceleratorVendor::Nvidia,
            "apple" => RuntimeAcceleratorVendor::Apple,
            other => RuntimeAcceleratorVendor::Other(
                TechnicalName::parse(other).map_err(|_| RuntimeError::CatalogInvalid)?,
            ),
        };
        let minimum_accelerator = self
            .minimum_accelerator_memory_gib
            .map(gibibytes)
            .transpose()?;
        RuntimeTarget::from_catalog(
            operating_system,
            architecture,
            vendor,
            TechnicalName::parse(&self.compute_architecture)
                .map_err(|_| RuntimeError::CatalogInvalid)?,
            u16::try_from(self.accelerator_count).map_err(|_| RuntimeError::CatalogInvalid)?,
            self.accelerator_partitioning,
            self.memory_topology,
            minimum_accelerator,
            gibibytes(self.minimum_total_memory_gib)?,
        )
    }

    // Returns whether this target can execute on one supported Rust Core host platform.
    pub(crate) fn is_core_platform(&self) -> bool {
        matches!(self.operating_system.as_str(), "linux" | "macos")
            && matches!(self.architecture.as_str(), "arm64" | "x86_64")
            && self.accelerator_count <= 64
            && TechnicalName::parse(&self.accelerator_vendor).is_ok()
            && TechnicalName::parse(&self.compute_architecture).is_ok()
    }
}

// Exposes one active catalog release identity for both list and install consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogListEntry {
    pub(crate) logical_model: LogicalModelName,
    pub(crate) target: RuntimeCatalogTarget,
    pub(crate) candidate_id: RuntimeCandidateId,
    pub(crate) version: String,
    pub(crate) source: RuntimeSource,
    pub(crate) engine: TechnicalName,
    pub(crate) engine_distribution: RuntimeCatalogEngineDistribution,
    pub(crate) model_uri: String,
    pub(crate) authors: Vec<RuntimeCatalogAuthor>,
    pub(crate) license: String,
    pub(crate) benchmark_score_bits: Option<u64>,
    pub(crate) provenance: Value,
    pub(crate) verification: Value,
    pub(crate) verification_method: String,
    pub(crate) consensus_sha256: Option<Sha256Digest>,
    pub(crate) recommended: bool,
}

impl RuntimeCatalogListEntry {
    // Returns the logical model exposed to users.
    pub const fn logical_model(&self) -> &LogicalModelName {
        &self.logical_model
    }

    // Returns the complete signed target contract.
    pub const fn target(&self) -> &RuntimeCatalogTarget {
        &self.target
    }

    // Returns the exact runtime candidate identity.
    pub const fn candidate_id(&self) -> &RuntimeCandidateId {
        &self.candidate_id
    }

    // Returns the exact published runtime version.
    pub fn version(&self) -> &str {
        &self.version
    }

    // Returns the immutable digest-pinned runtime source.
    pub const fn source(&self) -> &RuntimeSource {
        &self.source
    }

    // Returns the Engine name projected from the runtime manifest.
    pub const fn engine(&self) -> &TechnicalName {
        &self.engine
    }

    // Returns the compact signed Engine distribution identity.
    pub const fn engine_distribution(&self) -> &RuntimeCatalogEngineDistribution {
        &self.engine_distribution
    }

    // Returns the primary Hugging Face model URI projected by the catalog.
    pub fn model_uri(&self) -> &str {
        &self.model_uri
    }

    // Returns ordered structured authors without flattening their identities.
    pub fn authors(&self) -> &[RuntimeCatalogAuthor] {
        &self.authors
    }

    // Returns the SPDX license identifier projected by publication metadata.
    pub fn license(&self) -> &str {
        &self.license
    }

    // Returns the signed evidence label without turning it into an install gate.
    pub const fn evidence_label(&self) -> EvidenceLabel {
        EvidenceLabel::Qualified
    }

    // Returns whether this exact release is the active recommendation.
    pub const fn is_recommended(&self) -> bool {
        self.recommended
    }

    // Returns the positive finite recommendation score when present.
    pub fn benchmark_score(&self) -> Option<f64> {
        self.benchmark_score_bits.map(f64::from_bits)
    }

    // Returns the qualification method retained by the signed catalog.
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    // Returns the complete semantically validated qualification projection.
    pub const fn verification_document(&self) -> &Value {
        &self.verification
    }

    // Returns the complete semantically validated publication provenance projection.
    pub const fn provenance_document(&self) -> &Value {
        &self.provenance
    }

    // Returns the revocable consensus identity when this release carries one.
    pub const fn consensus_sha256(&self) -> Option<&Sha256Digest> {
        self.consensus_sha256.as_ref()
    }
}

// Hydrates exact runtime-pack fields that are deliberately absent from catalog schema 7.
pub trait RuntimeCatalogCandidateHydrator: Send + Sync {
    // Resolves and verifies one exact signed release into a complete runtime candidate.
    fn hydrate(&self, release: &RuntimeCatalogListEntry) -> Result<RuntimeCandidate, RuntimeError>;
}

// Controls refresh and stale fallback for one signed snapshot load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCatalogLoadOptions {
    refresh: bool,
    allow_stale: bool,
}

impl RuntimeCatalogLoadOptions {
    // Creates ordinary cache-first loading with verified stale fallback on network failure.
    pub const fn ordinary() -> Self {
        Self {
            refresh: false,
            allow_stale: true,
        }
    }

    // Creates an explicit refresh with configurable stale fallback.
    pub const fn refresh(allow_stale: bool) -> Self {
        Self {
            refresh: true,
            allow_stale,
        }
    }
}

// Carries one verified active catalog view and its freshness identity.
#[derive(Clone)]
pub struct RuntimeCatalogSnapshot {
    source: String,
    catalog_sha256: Sha256Digest,
    revocations_sha256: Sha256Digest,
    revocation_sequence: u64,
    verified_at_unix: u64,
    stale: bool,
    catalog: Arc<ActiveCatalog>,
}

impl RuntimeCatalogSnapshot {
    // Returns the exact configured catalog source.
    pub fn source(&self) -> &str {
        &self.source
    }

    // Returns the SHA-256 of exact signed catalog bytes.
    pub const fn catalog_sha256(&self) -> &Sha256Digest {
        &self.catalog_sha256
    }

    // Returns the SHA-256 of exact signed revocation bytes.
    pub const fn revocations_sha256(&self) -> &Sha256Digest {
        &self.revocations_sha256
    }

    // Returns the monotonic sequence of the verified revocation ledger.
    pub const fn revocation_sequence(&self) -> u64 {
        self.revocation_sequence
    }

    // Returns when both documents were verified together.
    pub const fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    // Returns whether a network-unavailable refresh reused this verified object.
    pub const fn is_stale(&self) -> bool {
        self.stale
    }
}

impl std::fmt::Debug for RuntimeCatalogSnapshot {
    // Presents snapshot identity and freshness without dumping signed catalog contents.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCatalogSnapshot")
            .field("source", &self.source)
            .field("catalog_sha256", &self.catalog_sha256)
            .field("revocations_sha256", &self.revocations_sha256)
            .field("revocation_sequence", &self.revocation_sequence)
            .field("verified_at_unix", &self.verified_at_unix)
            .field("stale", &self.stale)
            .finish_non_exhaustive()
    }
}

// Carries one verified signed snapshot and the exact releases selected from that snapshot.
#[derive(Clone, Debug)]
pub struct RuntimeCatalogListing {
    snapshot: RuntimeCatalogSnapshot,
    entries: Vec<RuntimeCatalogListEntry>,
}

impl RuntimeCatalogListing {
    // Returns the signed snapshot identity shared by every returned release.
    pub const fn snapshot(&self) -> &RuntimeCatalogSnapshot {
        &self.snapshot
    }

    // Returns the ordered active releases selected from the signed snapshot.
    pub fn entries(&self) -> &[RuntimeCatalogListEntry] {
        &self.entries
    }

    // Transfers the ordered active releases without cloning catalog projections.
    pub fn into_entries(self) -> Vec<RuntimeCatalogListEntry> {
        self.entries
    }
}

// Owns signed catalog resolution, active revocation projection, and verified cache replay.
pub struct SignedRuntimeCatalogProvider {
    source: String,
    maximum_age_seconds: u64,
    http: Arc<dyn RuntimeHttpClient>,
    signatures: Arc<dyn RuntimeCatalogSignatureVerifier>,
    trust: Arc<dyn RuntimeCatalogTrustProvider>,
    cache: Arc<dyn RuntimeCatalogCache>,
    hydrator: Arc<dyn RuntimeCatalogCandidateHydrator>,
    clock: Arc<dyn RuntimeCatalogClock>,
}

impl SignedRuntimeCatalogProvider {
    // Returns the exact configured catalog source without loading or refreshing it.
    pub fn source(&self) -> &str {
        &self.source
    }

    // Creates one provider from explicit transport, trust, cache, hydration, and time ports.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: String,
        maximum_age_seconds: u64,
        http: Arc<dyn RuntimeHttpClient>,
        signatures: Arc<dyn RuntimeCatalogSignatureVerifier>,
        trust: Arc<dyn RuntimeCatalogTrustProvider>,
        cache: Arc<dyn RuntimeCatalogCache>,
        hydrator: Arc<dyn RuntimeCatalogCandidateHydrator>,
        clock: Arc<dyn RuntimeCatalogClock>,
    ) -> Result<Self, RuntimeError> {
        if !is_https_url(&source)
            || !source.ends_with("/catalog.json")
            || maximum_age_seconds == 0
            || maximum_age_seconds > 30 * 24 * 60 * 60
        {
            return Err(RuntimeError::CatalogInvalid);
        }
        Ok(Self {
            source,
            maximum_age_seconds,
            http,
            signatures,
            trust,
            cache,
            hydrator,
            clock,
        })
    }

    // Creates one provider with the ordinary one-hour freshness boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn ordinary(
        source: String,
        http: Arc<dyn RuntimeHttpClient>,
        signatures: Arc<dyn RuntimeCatalogSignatureVerifier>,
        trust: Arc<dyn RuntimeCatalogTrustProvider>,
        cache: Arc<dyn RuntimeCatalogCache>,
        hydrator: Arc<dyn RuntimeCatalogCandidateHydrator>,
        clock: Arc<dyn RuntimeCatalogClock>,
    ) -> Result<Self, RuntimeError> {
        Self::new(
            source,
            DEFAULT_MAXIMUM_AGE_SECONDS,
            http,
            signatures,
            trust,
            cache,
            hydrator,
            clock,
        )
    }

    // Loads one complete signed catalog and revocation snapshot.
    pub fn load(
        &self,
        options: RuntimeCatalogLoadOptions,
    ) -> Result<RuntimeCatalogSnapshot, RuntimeError> {
        let now = self.clock.now_unix()?;
        let anchor = self.cache.read_revocation_anchor(&self.source)?;
        let cached = self
            .cache
            .read()
            .ok()
            .flatten()
            .filter(|entry| entry.source() == self.source)
            .and_then(|entry| {
                self.snapshot(&entry, now, false)
                    .ok()
                    .filter(|snapshot| anchor_accepts(anchor.as_ref(), snapshot))
                    .map(|snapshot| (entry, snapshot))
            });
        if let Some((_, snapshot)) = &cached {
            self.persist_revocation_anchor(snapshot)?;
        }
        if !options.refresh {
            if let Some((_, snapshot)) = &cached {
                if !snapshot.is_stale() {
                    return Ok(snapshot.clone());
                }
            }
        }
        match self.refresh(now, cached.as_ref().map(|(_, snapshot)| snapshot)) {
            Ok(snapshot) => Ok(snapshot),
            Err(RuntimeError::CatalogUnavailable) if options.allow_stale => cached
                .map(|(_, mut snapshot)| {
                    snapshot.stale = true;
                    snapshot
                })
                .ok_or(RuntimeError::CatalogUnavailable),
            Err(error) => Err(error),
        }
    }

    // Lists active releases through the same verified snapshot used for installation.
    pub fn list(
        &self,
        model: Option<&LogicalModelName>,
        hardware: Option<&HardwareObservation>,
        include_versions: bool,
        all_targets: bool,
    ) -> Result<Vec<RuntimeCatalogListEntry>, RuntimeError> {
        Ok(self
            .list_with_options(
                model,
                hardware,
                include_versions,
                all_targets,
                RuntimeCatalogLoadOptions::ordinary(),
            )?
            .into_entries())
    }

    // Lists releases from one explicitly selected cache or refresh policy.
    pub fn list_with_options(
        &self,
        model: Option<&LogicalModelName>,
        hardware: Option<&HardwareObservation>,
        include_versions: bool,
        all_targets: bool,
        options: RuntimeCatalogLoadOptions,
    ) -> Result<RuntimeCatalogListing, RuntimeError> {
        let snapshot = self.load(options)?;
        let entries = snapshot
            .catalog
            .entries(model, include_versions)
            .into_iter()
            .filter(|entry| {
                all_targets || hardware.is_some_and(|hardware| entry.target().matches(hardware))
            })
            .collect();
        Ok(RuntimeCatalogListing { snapshot, entries })
    }

    // Downloads, verifies, parses, and atomically caches one complete fresh snapshot.
    fn refresh(
        &self,
        now: u64,
        previous: Option<&RuntimeCatalogSnapshot>,
    ) -> Result<RuntimeCatalogSnapshot, RuntimeError> {
        let base = self.source.trim_end_matches("catalog.json");
        let entry = RuntimeCatalogCacheEntry::new(
            self.source.clone(),
            self.download(&self.source, MAXIMUM_CATALOG_BYTES)?,
            self.download(&format!("{}.sig", self.source), MAXIMUM_SIGNATURE_BYTES)?,
            self.download(&format!("{base}revocations.json"), MAXIMUM_LEDGER_BYTES)?,
            self.download(
                &format!("{base}revocations.json.sig"),
                MAXIMUM_SIGNATURE_BYTES,
            )?,
            now,
        )
        .map_err(|_| RuntimeError::CatalogInvalid)?;
        let snapshot = self.snapshot(&entry, now, false)?;
        if previous.is_some_and(|previous| {
            snapshot.revocation_sequence() < previous.revocation_sequence()
                || (snapshot.revocation_sequence() == previous.revocation_sequence()
                    && snapshot.revocations_sha256() != previous.revocations_sha256())
        }) {
            return Err(RuntimeError::CatalogInvalid);
        }
        let anchor = self.cache.read_revocation_anchor(&self.source)?;
        if !anchor_accepts(anchor.as_ref(), &snapshot) {
            return Err(RuntimeError::CatalogInvalid);
        }
        self.cache.write(&entry)?;
        self.persist_revocation_anchor(&snapshot)?;
        Ok(snapshot)
    }

    // Advances the independent anchor after one complete signed snapshot verifies.
    fn persist_revocation_anchor(
        &self,
        snapshot: &RuntimeCatalogSnapshot,
    ) -> Result<(), RuntimeError> {
        self.cache
            .write_revocation_anchor(&RuntimeCatalogRevocationAnchor::new(
                self.source.clone(),
                snapshot.revocation_sequence(),
                snapshot.revocations_sha256().clone(),
            )?)
    }

    // Downloads one exact bounded HTTPS body.
    fn download(&self, url: &str, maximum_bytes: u64) -> Result<Vec<u8>, RuntimeError> {
        let request =
            RuntimeHttpRequest::new(url, None, None, false, 15).map_err(map_download_error)?;
        let response = self
            .http
            .get(&request, maximum_bytes)
            .map_err(map_download_error)?;
        if response.status() != 200
            || !response.final_url().starts_with("https://")
            || response.body().is_empty()
            || response.body().len() as u64 > maximum_bytes
        {
            return Err(RuntimeError::CatalogInvalid);
        }
        Ok(response.body().to_vec())
    }

    // Verifies and parses one cached or downloaded complete byte set.
    fn snapshot(
        &self,
        entry: &RuntimeCatalogCacheEntry,
        now: u64,
        force_stale: bool,
    ) -> Result<RuntimeCatalogSnapshot, RuntimeError> {
        if entry.verified_at_unix() > now {
            return Err(RuntimeError::CatalogInvalid);
        }
        let trust = self.trust.trust_root()?;
        self.signatures.verify(
            RuntimeCatalogSignatureKind::Catalog,
            entry.catalog(),
            entry.catalog_signature(),
            &trust,
        )?;
        self.signatures.verify(
            RuntimeCatalogSignatureKind::Revocations,
            entry.revocations(),
            entry.revocations_signature(),
            &trust,
        )?;
        let catalog = parse_catalog(entry.catalog())?;
        let ledger = parse_revocations(entry.revocations())?;
        let catalog = Arc::new(apply_revocations(catalog, &ledger)?);
        Ok(RuntimeCatalogSnapshot {
            source: entry.source().to_string(),
            catalog_sha256: sha256_digest(entry.catalog()),
            revocations_sha256: sha256_digest(entry.revocations()),
            revocation_sequence: ledger.sequence(),
            verified_at_unix: entry.verified_at_unix(),
            stale: force_stale
                || now.saturating_sub(entry.verified_at_unix()) > self.maximum_age_seconds,
            catalog,
        })
    }

    // Hydrates and cross-checks one catalog release before RuntimeManager can consume it.
    fn hydrate(&self, entry: &RuntimeCatalogListEntry) -> Result<RuntimeCandidate, RuntimeError> {
        let candidate = self.hydrator.hydrate(entry)?;
        let expected_target = entry.target.runtime_target()?;
        let runtime = candidate.runtime();
        let model_uri_matches = candidate
            .artifacts()
            .first()
            .is_some_and(|artifact| artifact.uri().as_str() == entry.model_uri);
        if candidate.logical_model() != entry.logical_model()
            || runtime.candidate_id() != entry.candidate_id()
            || runtime.version().as_str() != entry.version()
            || runtime.target_id() != entry.target.id()
            || runtime.source() != entry.source()
            || !entry
                .engine_distribution
                .matches(runtime.engine_distribution())
            || candidate.target != expected_target
            || candidate.evidence_label != EvidenceLabel::Qualified
            || candidate.engine_protocol != ENGINE_PROTOCOL_VERSION
            || candidate.recommended != entry.recommended
            || candidate.revoked
            || !model_uri_matches
        {
            return Err(RuntimeError::CatalogInvalid);
        }
        Ok(candidate)
    }
}

impl RuntimeCatalogProvider for SignedRuntimeCatalogProvider {
    // Returns only current install-selection releases from one verified active snapshot.
    fn candidates(&self, model: &LogicalModelName) -> Result<Vec<RuntimeCandidate>, RuntimeError> {
        let snapshot = self.load(RuntimeCatalogLoadOptions::ordinary())?;
        snapshot
            .catalog
            .selection_entries(model)
            .iter()
            .map(|entry| self.hydrate(entry))
            .collect()
    }
}

// Maps transport-specific errors into availability or authenticated-input failure.
fn map_download_error(error: RuntimeError) -> RuntimeError {
    match error {
        RuntimeError::DownloadUnavailable => RuntimeError::CatalogUnavailable,
        _ => RuntimeError::CatalogInvalid,
    }
}

// Requires one snapshot to preserve or advance the durable revocation anchor exactly.
fn anchor_accepts(
    anchor: Option<&RuntimeCatalogRevocationAnchor>,
    snapshot: &RuntimeCatalogSnapshot,
) -> bool {
    anchor.is_none_or(|anchor| {
        snapshot.source() == anchor.source()
            && (snapshot.revocation_sequence() > anchor.sequence()
                || (snapshot.revocation_sequence() == anchor.sequence()
                    && snapshot.revocations_sha256() == anchor.revocations_sha256()))
    })
}

// Returns one SHA-256 value from exact bytes.
pub(crate) fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    let value: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Sha256Digest::parse(&value).expect("SHA-256 output")
}

// Returns the standard SubjectPublicKeyInfo DER encoding for one Ed25519 key.
fn ed25519_public_key_der(public_key: &[u8; 32]) -> Vec<u8> {
    let mut result = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    result.extend_from_slice(public_key);
    result
}

// Binds exact catalog and revocation bytes into one immutable snapshot identity.
fn snapshot_digest(catalog: &[u8], revocations: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    for (label, value) in [
        (b"letsinfer.catalog.v1\0".as_slice(), catalog),
        (b"letsinfer.revocations.v1\0".as_slice(), revocations),
    ] {
        digest.update(label);
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    let value: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Sha256Digest::parse(&value).expect("SHA-256 output")
}

// Serializes one JSON value with sorted keys, compact separators, and one trailing newline.
pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| RuntimeError::CatalogInvalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// Creates one private directory or validates an existing private directory.
fn create_private_directory(path: &Path) -> Result<(), RuntimeError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    }
    validate_private_directory(path)
}

// Creates one exact new owner-only directory.
fn create_new_private_directory(path: &Path) -> Result<(), RuntimeError> {
    fs::create_dir(path).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)
}

// Validates one owner-only non-symlink directory.
fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(RuntimeError::CatalogCacheUnavailable);
    }
    Ok(())
}

// Writes one new owner-readable regular file and syncs its contents.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)
}

// Reads one bounded owner-only regular file without following its final path.
fn read_private_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, RuntimeError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes
    {
        return Err(RuntimeError::CatalogCacheUnavailable);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(RuntimeError::CatalogCacheUnavailable);
    }
    Ok(bytes)
}

// Returns one random lowercase identity for a private temporary path.
fn random_identity() -> Result<String, RuntimeError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RuntimeError::CatalogCacheUnavailable)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
