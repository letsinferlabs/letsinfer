// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

use sha2::{Digest, Sha256};

use crate::{
    maximum_watchdog_targets, watchdog_crc32, WatchdogError, WatchdogProtectedEngine,
    WatchdogProtectionPhase,
};

const WATCHDOG_CONTROLLER_ALLOWLIST_MAX_BYTES: usize = 12_288;
pub(crate) const WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES: usize = 1_048_576;
const WATCHDOG_CONTROLLER_ID_BYTES: usize = 32;
const WATCHDOG_CONTROLLER_FINGERPRINT_BYTES: usize = 64;
const WATCHDOG_INSTALLATION_ID_BYTES: usize = 64;

// Persists exact canonical registry snapshots under optimistic byte identity.
pub trait WatchdogControllerSnapshotProvider: Send + Sync {
    // Loads the complete current snapshot or reports that no registry exists yet.
    fn load(&self) -> Result<Option<Vec<u8>>, WatchdogError>;

    // Atomically replaces exactly the snapshot the caller previously loaded.
    fn commit(
        &self,
        expected_snapshot: Option<&[u8]>,
        snapshot: &[u8],
    ) -> Result<(), WatchdogError>;
}

// Stores the exact version-one controller allowlist consumed by the C daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogControllerAllowlist {
    installation_id: String,
    controllers: BTreeMap<String, String>,
    sha256: String,
}

impl WatchdogControllerAllowlist {
    // Parses one bounded allowlist without widening its existing C vocabulary.
    pub fn parse(source: &[u8]) -> Result<Self, WatchdogError> {
        if source.is_empty()
            || source.len() > WATCHDOG_CONTROLLER_ALLOWLIST_MAX_BYTES
            || source.last() != Some(&b'\n')
            || source.contains(&0)
        {
            return Err(controller_error("controller allowlist framing is invalid"));
        }
        let source = std::str::from_utf8(source)
            .map_err(|_| controller_error("controller allowlist text is invalid"))?;
        let mut version_seen = false;
        let mut installation_id = None;
        let mut controllers = BTreeMap::new();
        let mut fingerprints = BTreeSet::new();
        for line in source
            .split_terminator('\n')
            .filter(|line| !line.is_empty())
        {
            if line == "version=1" {
                if version_seen || installation_id.is_some() || !controllers.is_empty() {
                    return Err(controller_error("controller allowlist order is invalid"));
                }
                version_seen = true;
                continue;
            }
            if let Some(value) = line.strip_prefix("installation_id=") {
                if !version_seen
                    || installation_id.is_some()
                    || !controllers.is_empty()
                    || !lower_hex(value, WATCHDOG_INSTALLATION_ID_BYTES)
                {
                    return Err(controller_error(
                        "controller installation identity is invalid",
                    ));
                }
                installation_id = Some(value.to_string());
                continue;
            }
            let value = line
                .strip_prefix("controller=")
                .ok_or_else(|| controller_error("controller allowlist field is unknown"))?;
            if !version_seen
                || installation_id.is_none()
                || controllers.len() >= maximum_watchdog_targets()
            {
                return Err(controller_error("controller allowlist bounds are invalid"));
            }
            let mut fields = value.split(',');
            let controller_id = fields.next().unwrap_or_default();
            let certificate_sha256 = fields.next().unwrap_or_default();
            if fields.next().is_some()
                || !lower_hex(controller_id, WATCHDOG_CONTROLLER_ID_BYTES)
                || !lower_hex(certificate_sha256, WATCHDOG_CONTROLLER_FINGERPRINT_BYTES)
                || controllers.contains_key(controller_id)
                || !fingerprints.insert(certificate_sha256.to_string())
            {
                return Err(controller_error("controller allowlist entry is invalid"));
            }
            controllers.insert(controller_id.to_string(), certificate_sha256.to_string());
        }
        let installation_id = installation_id
            .filter(|_| version_seen && !controllers.is_empty())
            .ok_or_else(|| controller_error("controller allowlist is incomplete"))?;
        let canonical = canonical_allowlist(&installation_id, &controllers);
        let sha256 = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        Ok(Self {
            installation_id,
            controllers,
            sha256,
        })
    }

    // Returns the installation identity bound to every authorized controller.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    // Returns the exact number of authorized controller identities.
    pub fn controller_count(&self) -> usize {
        self.controllers.len()
    }

    // Returns the canonical identity of the complete installation-bound authorization set.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    // Returns whether one identity and certificate fingerprint are paired.
    pub fn authorizes(&self, controller_id: &str, certificate_sha256: &str) -> bool {
        self.controllers
            .get(controller_id)
            .is_some_and(|fingerprint| fingerprint == certificate_sha256)
    }

    // Returns the controller identity paired with one certificate fingerprint.
    pub fn controller_id_for_fingerprint(&self, certificate_sha256: &str) -> Option<&str> {
        self.controllers
            .iter()
            .find(|(_, fingerprint)| fingerprint.as_str() == certificate_sha256)
            .map(|(controller_id, _)| controller_id.as_str())
    }
}

// Encodes one parsed allowlist in the only canonical order used for reload identity.
fn canonical_allowlist(installation_id: &str, controllers: &BTreeMap<String, String>) -> String {
    let mut document = format!("version=1\ninstallation_id={installation_id}\n");
    for (controller_id, fingerprint) in controllers {
        document.push_str(&format!("controller={controller_id},{fingerprint}\n"));
    }
    document
}

// Binds one authorized controller session to one exact protected process generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogControllerBinding {
    controller_id: String,
    certificate_sha256: String,
    session_generation: u64,
    target: WatchdogProtectedEngine,
}

impl WatchdogControllerBinding {
    // Creates one active process-bound controller session.
    pub fn new(
        controller_id: &str,
        certificate_sha256: &str,
        session_generation: u64,
        target: WatchdogProtectedEngine,
    ) -> Result<Self, WatchdogError> {
        if !lower_hex(controller_id, WATCHDOG_CONTROLLER_ID_BYTES)
            || !lower_hex(certificate_sha256, WATCHDOG_CONTROLLER_FINGERPRINT_BYTES)
            || session_generation == 0
            || !matches!(
                target.phase(),
                WatchdogProtectionPhase::Starting | WatchdogProtectionPhase::Armed
            )
            || target.container_id().is_none()
            || target.process_id().is_none()
            || target.process_start_ticks().is_none()
            || target.boot_id().is_none()
            || target.cgroup().is_none()
        {
            return Err(controller_error("controller binding is invalid"));
        }
        Ok(Self {
            controller_id: controller_id.to_string(),
            certificate_sha256: certificate_sha256.to_string(),
            session_generation,
            target,
        })
    }

    // Returns the exact authorized controller identity.
    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    // Returns the exact authorized certificate fingerprint.
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }

    // Returns the monotonic controller-owned session generation.
    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    // Returns the exact protected process identity controlled by this session.
    pub const fn target(&self) -> &WatchdogProtectedEngine {
        &self.target
    }
}

// Identifies the closed result of one accepted controller-registry operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogControllerMutationKind {
    Created,
    Advanced,
    Replayed,
    Retired,
}

// Returns the registry revision observed after one accepted operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogControllerMutation {
    kind: WatchdogControllerMutationKind,
    revision: u64,
}

impl WatchdogControllerMutation {
    // Creates one closed mutation result at its resulting revision.
    const fn new(kind: WatchdogControllerMutationKind, revision: u64) -> Self {
        Self { kind, revision }
    }

    // Returns whether the operation created, advanced, replayed, or retired state.
    pub const fn kind(self) -> WatchdogControllerMutationKind {
        self.kind
    }

    // Returns the current optimistic concurrency revision.
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

// Owns bounded live controller sessions and restart-safe generation tombstones.
pub struct WatchdogControllerRegistry {
    allowlist: WatchdogControllerAllowlist,
    maximum_active_bindings: usize,
    snapshot_provider: Option<Arc<dyn WatchdogControllerSnapshotProvider>>,
    state: Mutex<WatchdogControllerRegistryState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WatchdogControllerRegistryState {
    revision: u64,
    entries: BTreeMap<String, WatchdogControllerEntry>,
    persisted_snapshot: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WatchdogControllerEntry {
    session_generation: u64,
    binding: Option<WatchdogControllerBinding>,
}

impl WatchdogControllerRegistry {
    // Creates one empty bounded registry for an exact version-one allowlist.
    pub fn new(
        allowlist: WatchdogControllerAllowlist,
        maximum_active_bindings: usize,
    ) -> Result<Self, WatchdogError> {
        validate_registry_bound(maximum_active_bindings)?;
        Ok(Self {
            allowlist,
            maximum_active_bindings,
            snapshot_provider: None,
            state: Mutex::new(WatchdogControllerRegistryState {
                revision: 1,
                entries: BTreeMap::new(),
                persisted_snapshot: None,
            }),
        })
    }

    // Reconstructs or initializes one registry before it can authorize a connection.
    pub fn open_persistent(
        allowlist: WatchdogControllerAllowlist,
        maximum_active_bindings: usize,
        snapshot_provider: Arc<dyn WatchdogControllerSnapshotProvider>,
    ) -> Result<Self, WatchdogError> {
        validate_registry_bound(maximum_active_bindings)?;
        let loaded = snapshot_provider.load()?;
        let mut state = match loaded.as_deref() {
            Some(snapshot) => parse_snapshot(&allowlist, maximum_active_bindings, snapshot)?,
            None => WatchdogControllerRegistryState {
                revision: 1,
                entries: BTreeMap::new(),
                persisted_snapshot: None,
            },
        };
        let canonical = encode_snapshot(&allowlist, &state)?;
        match loaded {
            Some(snapshot) if snapshot != canonical => {
                return Err(controller_error(
                    "controller registry snapshot is not canonical",
                ))
            }
            Some(snapshot) => state.persisted_snapshot = Some(snapshot),
            None => {
                snapshot_provider.commit(None, &canonical)?;
                state.persisted_snapshot = Some(canonical);
            }
        }
        Ok(Self {
            allowlist,
            maximum_active_bindings,
            snapshot_provider: Some(snapshot_provider),
            state: Mutex::new(state),
        })
    }

    // Applies one authorized session under optimistic revision and generation checks.
    pub fn apply(
        &self,
        binding: WatchdogControllerBinding,
        expected_revision: u64,
    ) -> Result<WatchdogControllerMutation, WatchdogError> {
        if !self
            .allowlist
            .authorizes(binding.controller_id(), binding.certificate_sha256())
        {
            return Err(controller_error("controller is not authorized"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        require_revision(state.revision, expected_revision)?;
        let existing = state.entries.get(binding.controller_id()).cloned();
        if let Some(existing) = &existing {
            if binding.session_generation() < existing.session_generation {
                return Err(controller_error("controller session generation is stale"));
            }
            if binding.session_generation() == existing.session_generation {
                return match &existing.binding {
                    Some(existing_binding) if *existing_binding == binding => {
                        Ok(WatchdogControllerMutation::new(
                            WatchdogControllerMutationKind::Replayed,
                            state.revision,
                        ))
                    }
                    Some(_) => Err(controller_error("controller session generation conflicts")),
                    None => Err(controller_error("controller session generation is retired")),
                };
            }
        }
        reject_target_conflict(&state.entries, &binding)?;
        let replacing_active = state
            .entries
            .get(binding.controller_id())
            .is_some_and(|entry| entry.binding.is_some());
        if !replacing_active && active_binding_count(&state.entries) >= self.maximum_active_bindings
        {
            return Err(controller_error("controller registry is full"));
        }
        let kind = if existing.is_some() {
            WatchdogControllerMutationKind::Advanced
        } else {
            WatchdogControllerMutationKind::Created
        };
        let mut candidate = state.clone();
        candidate.entries.insert(
            binding.controller_id().to_string(),
            WatchdogControllerEntry {
                session_generation: binding.session_generation(),
                binding: Some(binding),
            },
        );
        candidate.revision = next_revision(state.revision)?;
        self.commit_candidate(&mut state, candidate)?;
        Ok(WatchdogControllerMutation::new(kind, state.revision))
    }

    // Retires exactly one current session while preserving its anti-replay generation.
    pub fn retire(
        &self,
        controller_id: &str,
        session_generation: u64,
        expected_revision: u64,
    ) -> Result<WatchdogControllerMutation, WatchdogError> {
        if !lower_hex(controller_id, WATCHDOG_CONTROLLER_ID_BYTES) || session_generation == 0 {
            return Err(controller_error(
                "controller retirement identity is invalid",
            ));
        }
        if !self.allowlist.controllers.contains_key(controller_id) {
            return Err(controller_error("controller is not authorized"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        require_revision(state.revision, expected_revision)?;
        let entry = state
            .entries
            .get_mut(controller_id)
            .ok_or_else(|| controller_error("controller session generation is stale"))?;
        if session_generation < entry.session_generation {
            return Err(controller_error("controller session generation is stale"));
        }
        if session_generation > entry.session_generation {
            return Err(controller_error("controller session generation conflicts"));
        }
        if entry.binding.is_none() {
            return Ok(WatchdogControllerMutation::new(
                WatchdogControllerMutationKind::Replayed,
                state.revision,
            ));
        }
        let mut candidate = state.clone();
        candidate
            .entries
            .get_mut(controller_id)
            .ok_or_else(|| controller_error("controller session generation is stale"))?
            .binding = None;
        candidate.revision = next_revision(state.revision)?;
        self.commit_candidate(&mut state, candidate)?;
        Ok(WatchdogControllerMutation::new(
            WatchdogControllerMutationKind::Retired,
            state.revision,
        ))
    }

    // Returns the current optimistic concurrency revision.
    pub fn revision(&self) -> Result<u64, WatchdogError> {
        self.state
            .lock()
            .map(|state| state.revision)
            .map_err(|_| WatchdogError::StateUnavailable)
    }

    // Returns every active binding in deterministic controller-identity order.
    pub fn active_bindings(&self) -> Result<Vec<WatchdogControllerBinding>, WatchdogError> {
        self.state
            .lock()
            .map(|state| {
                state
                    .entries
                    .values()
                    .filter_map(|entry| entry.binding.clone())
                    .collect()
            })
            .map_err(|_| WatchdogError::StateUnavailable)
    }

    // Returns whether one exact controller session remains the active registry binding.
    pub fn is_active(&self, binding: &WatchdogControllerBinding) -> Result<bool, WatchdogError> {
        self.state
            .lock()
            .map(|state| {
                state
                    .entries
                    .get(binding.controller_id())
                    .and_then(|entry| entry.binding.as_ref())
                    == Some(binding)
            })
            .map_err(|_| WatchdogError::StateUnavailable)
    }

    // Returns whether every accepted mutation commits an exact restart snapshot first.
    pub const fn is_persistent(&self) -> bool {
        self.snapshot_provider.is_some()
    }

    // Encodes deterministic restart state with one checksum over the complete body.
    pub fn snapshot(&self) -> Result<Vec<u8>, WatchdogError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        encode_snapshot(&self.allowlist, &state)
    }

    // Reconstructs one registry only from a complete canonical restart snapshot.
    pub fn from_snapshot(
        allowlist: WatchdogControllerAllowlist,
        maximum_active_bindings: usize,
        snapshot: &[u8],
    ) -> Result<Self, WatchdogError> {
        let parsed = parse_snapshot(&allowlist, maximum_active_bindings, snapshot)?;
        Ok(Self {
            allowlist,
            maximum_active_bindings,
            snapshot_provider: None,
            state: Mutex::new(parsed),
        })
    }

    // Builds and persists one allowlist replacement without mutating this last-good registry.
    fn replacement(&self, allowlist: WatchdogControllerAllowlist) -> Result<Self, WatchdogError> {
        if allowlist.installation_id() != self.allowlist.installation_id() {
            return Err(controller_error(
                "controller replacement installation identity differs",
            ));
        }
        validate_registry_bound(self.maximum_active_bindings)?;
        let state = self
            .state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let mut candidate = state.clone();
        candidate.entries.retain(|controller_id, entry| {
            let certificate = entry
                .binding
                .as_ref()
                .map(|binding| binding.certificate_sha256())
                .or_else(|| {
                    self.allowlist
                        .controllers
                        .get(controller_id)
                        .map(String::as_str)
                });
            certificate.is_some_and(|certificate| allowlist.authorizes(controller_id, certificate))
        });
        candidate.revision = next_revision(state.revision)?;
        if let Some(provider) = &self.snapshot_provider {
            let snapshot = encode_snapshot(&allowlist, &candidate)?;
            provider.commit(state.persisted_snapshot.as_deref(), &snapshot)?;
            candidate.persisted_snapshot = Some(snapshot);
        } else {
            candidate.persisted_snapshot = None;
        }
        Ok(Self {
            allowlist,
            maximum_active_bindings: self.maximum_active_bindings,
            snapshot_provider: self.snapshot_provider.clone(),
            state: Mutex::new(candidate),
        })
    }

    // Persists one candidate before making its state visible to registry readers.
    fn commit_candidate(
        &self,
        current: &mut WatchdogControllerRegistryState,
        mut candidate: WatchdogControllerRegistryState,
    ) -> Result<(), WatchdogError> {
        if let Some(provider) = &self.snapshot_provider {
            let snapshot = encode_snapshot(&self.allowlist, &candidate)?;
            provider.commit(current.persisted_snapshot.as_deref(), &snapshot)?;
            candidate.persisted_snapshot = Some(snapshot);
        }
        *current = candidate;
        Ok(())
    }
}

// Owns the atomic last-good registry identity used by listener leases and reload.
pub struct WatchdogControllerRegistryStore {
    state: RwLock<WatchdogControllerRegistryStoreState>,
}

struct WatchdogControllerRegistryStoreState {
    generation: u64,
    registry: Arc<WatchdogControllerRegistry>,
}

impl WatchdogControllerRegistryStore {
    // Creates one reloadable store around an already reconstructed registry.
    pub fn new(registry: Arc<WatchdogControllerRegistry>) -> Self {
        Self {
            state: RwLock::new(WatchdogControllerRegistryStoreState {
                generation: 1,
                registry,
            }),
        }
    }

    // Returns the current registry and its exact in-process trust generation.
    pub fn current(&self) -> Result<(u64, Arc<WatchdogControllerRegistry>), WatchdogError> {
        self.state
            .read()
            .map(|state| (state.generation, state.registry.clone()))
            .map_err(|_| WatchdogError::StateUnavailable)
    }

    // Returns whether one lease still belongs to the current trust generation.
    pub fn is_current(
        &self,
        generation: u64,
        registry: &Arc<WatchdogControllerRegistry>,
    ) -> Result<bool, WatchdogError> {
        self.state
            .read()
            .map(|state| generation == state.generation && Arc::ptr_eq(registry, &state.registry))
            .map_err(|_| WatchdogError::StateUnavailable)
    }

    // Persists and atomically installs one valid replacement while retaining failures unchanged.
    pub fn reload(&self, allowlist: WatchdogControllerAllowlist) -> Result<u64, WatchdogError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| WatchdogError::StateUnavailable)?;
        let replacement = Arc::new(state.registry.replacement(allowlist)?);
        let generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| controller_error("controller reload generation overflowed"))?;
        state.registry = replacement;
        state.generation = generation;
        Ok(generation)
    }
}

// Requires one active-session bound inside both the native and allowlist capacities.
fn validate_registry_bound(maximum_active_bindings: usize) -> Result<(), WatchdogError> {
    if maximum_active_bindings == 0 || maximum_active_bindings > maximum_watchdog_targets() {
        return Err(controller_error("controller registry bound is invalid"));
    }
    Ok(())
}

// Encodes one canonical registry state with its exact schema identity and checksum.
fn encode_snapshot(
    allowlist: &WatchdogControllerAllowlist,
    state: &WatchdogControllerRegistryState,
) -> Result<Vec<u8>, WatchdogError> {
    let mut body = format!(
        "schema=li_watchdog.controller-registry\nversion=1\ninstallation_id={}\nallowlist_sha256={}\nrevision={}\n",
        allowlist.installation_id(),
        allowlist.sha256(),
        state.revision
    );
    for (controller_id, entry) in &state.entries {
        let (certificate_sha256, active, descriptor) = match &entry.binding {
            Some(binding) => (
                binding.certificate_sha256(),
                "1",
                hex_encode(target_descriptor(binding.target()).as_bytes()),
            ),
            None => (
                allowlist.controllers[controller_id].as_str(),
                "0",
                "-".to_string(),
            ),
        };
        body.push_str(&format!(
            "entry={controller_id},{certificate_sha256},{},{active},{descriptor}\n",
            entry.session_generation
        ));
    }
    let checksum = watchdog_crc32(body.as_bytes());
    body.push_str(&format!("checksum={checksum:08x}\n"));
    if body.len() > WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES {
        return Err(controller_error(
            "controller registry snapshot is oversized",
        ));
    }
    Ok(body.into_bytes())
}

// Parses and verifies one closed deterministic restart snapshot.
fn parse_snapshot(
    allowlist: &WatchdogControllerAllowlist,
    maximum_active_bindings: usize,
    snapshot: &[u8],
) -> Result<WatchdogControllerRegistryState, WatchdogError> {
    if maximum_active_bindings == 0
        || maximum_active_bindings > maximum_watchdog_targets()
        || snapshot.is_empty()
        || snapshot.len() > WATCHDOG_CONTROLLER_SNAPSHOT_MAX_BYTES
        || snapshot.last() != Some(&b'\n')
        || snapshot.contains(&0)
    {
        return Err(controller_error(
            "controller registry snapshot framing is invalid",
        ));
    }
    let text = std::str::from_utf8(snapshot)
        .map_err(|_| controller_error("controller registry snapshot text is invalid"))?;
    let checksum_start = text
        .rfind("checksum=")
        .filter(|index| *index > 0 && text.as_bytes()[index - 1] == b'\n')
        .ok_or_else(|| controller_error("controller registry snapshot checksum is missing"))?;
    let body = &text[..checksum_start];
    let checksum_line = &text[checksum_start..text.len() - 1];
    let checksum = checksum_line
        .strip_prefix("checksum=")
        .filter(|value| lower_hex(value, 8))
        .ok_or_else(|| controller_error("controller registry snapshot checksum is invalid"))?;
    let expected = u32::from_str_radix(checksum, 16)
        .map_err(|_| controller_error("controller registry snapshot checksum is invalid"))?;
    if watchdog_crc32(body.as_bytes()) != expected {
        return Err(controller_error(
            "controller registry snapshot checksum does not match",
        ));
    }
    let mut lines = body.split_terminator('\n');
    if lines.next() != Some("schema=li_watchdog.controller-registry")
        || lines.next() != Some("version=1")
        || lines
            .next()
            .and_then(|line| line.strip_prefix("installation_id="))
            != Some(allowlist.installation_id())
        || lines
            .next()
            .and_then(|line| line.strip_prefix("allowlist_sha256="))
            != Some(allowlist.sha256())
    {
        return Err(controller_error(
            "controller registry snapshot identity is invalid",
        ));
    }
    let revision = parse_positive(
        lines
            .next()
            .and_then(|line| line.strip_prefix("revision="))
            .ok_or_else(|| controller_error("controller registry snapshot revision is missing"))?,
        "controller registry snapshot revision is invalid",
    )?;
    let mut entries = BTreeMap::new();
    let mut previous_controller_id: Option<String> = None;
    for line in lines {
        let value = line
            .strip_prefix("entry=")
            .ok_or_else(|| controller_error("controller registry snapshot field is unknown"))?;
        let mut fields = value.split(',');
        let controller_id = fields.next().unwrap_or_default();
        let certificate_sha256 = fields.next().unwrap_or_default();
        let session_generation = fields.next().unwrap_or_default();
        let active = fields.next().unwrap_or_default();
        let descriptor = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || !allowlist.authorizes(controller_id, certificate_sha256)
            || entries.len() >= allowlist.controller_count()
            || entries.contains_key(controller_id)
        {
            return Err(controller_error(
                "controller registry snapshot entry is invalid",
            ));
        }
        if previous_controller_id
            .as_deref()
            .is_some_and(|previous| previous >= controller_id)
        {
            return Err(controller_error(
                "controller registry snapshot order is invalid",
            ));
        }
        let session_generation = parse_positive(
            session_generation,
            "controller registry snapshot generation is invalid",
        )?;
        let binding = match active {
            "0" if descriptor == "-" => None,
            "1" => {
                let descriptor = hex_decode(descriptor)?;
                let descriptor = String::from_utf8(descriptor).map_err(|_| {
                    controller_error("controller registry snapshot descriptor is invalid")
                })?;
                let target = WatchdogProtectedEngine::parse(&descriptor)?;
                if target_descriptor(&target) != descriptor {
                    return Err(controller_error(
                        "controller registry snapshot descriptor is not canonical",
                    ));
                }
                Some(WatchdogControllerBinding::new(
                    controller_id,
                    certificate_sha256,
                    session_generation,
                    target,
                )?)
            }
            _ => {
                return Err(controller_error(
                    "controller registry snapshot active state is invalid",
                ))
            }
        };
        if let Some(binding) = &binding {
            reject_target_conflict(&entries, binding)?;
        }
        entries.insert(
            controller_id.to_string(),
            WatchdogControllerEntry {
                session_generation,
                binding,
            },
        );
        previous_controller_id = Some(controller_id.to_string());
    }
    if active_binding_count(&entries) > maximum_active_bindings || revision <= entries.len() as u64
    {
        return Err(controller_error(
            "controller registry snapshot exceeds its bound",
        ));
    }
    Ok(WatchdogControllerRegistryState {
        revision,
        entries,
        persisted_snapshot: None,
    })
}

// Rejects a process or protection generation already controlled by another identity.
fn reject_target_conflict(
    entries: &BTreeMap<String, WatchdogControllerEntry>,
    candidate: &WatchdogControllerBinding,
) -> Result<(), WatchdogError> {
    if entries.iter().any(|(controller_id, entry)| {
        controller_id.as_str() != candidate.controller_id()
            && entry
                .binding
                .as_ref()
                .is_some_and(|binding| targets_conflict(binding.target(), candidate.target()))
    }) {
        return Err(controller_error("protected process is already controlled"));
    }
    Ok(())
}

// Returns whether two bindings claim the same protection generation or native process.
fn targets_conflict(left: &WatchdogProtectedEngine, right: &WatchdogProtectedEngine) -> bool {
    left.generation() == right.generation()
        || left.container_id() == right.container_id()
        || (left.process_id() == right.process_id()
            && left.process_start_ticks() == right.process_start_ticks()
            && left.boot_id() == right.boot_id()
            && left.cgroup() == right.cgroup())
}

// Returns the number of active sessions without counting anti-replay tombstones.
fn active_binding_count(entries: &BTreeMap<String, WatchdogControllerEntry>) -> usize {
    entries
        .values()
        .filter(|entry| entry.binding.is_some())
        .count()
}

// Requires the caller's optimistic revision to equal the current registry revision.
fn require_revision(current: u64, expected: u64) -> Result<(), WatchdogError> {
    if expected != current {
        return Err(controller_error("controller registry revision is stale"));
    }
    Ok(())
}

// Advances a positive registry revision without permitting integer wraparound.
fn next_revision(current: u64) -> Result<u64, WatchdogError> {
    current
        .checked_add(1)
        .ok_or_else(|| controller_error("controller registry revision is exhausted"))
}

// Serializes one protected target into the unchanged version-one descriptor.
fn target_descriptor(target: &WatchdogProtectedEngine) -> String {
    format!(
        "version=1\ngeneration={}\nphase={}\ncontainer_name={}\ncontainer_id={}\npid={}\nstart_ticks={}\nboot_id={}\ncgroup={}\n",
        target.generation(),
        protection_phase_text(target.phase()),
        target.container_name(),
        target.container_id().unwrap_or("-"),
        target
            .process_id()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        target
            .process_start_ticks()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        target.boot_id().unwrap_or("-"),
        target.cgroup().unwrap_or("-")
    )
}

// Returns the unchanged lower-underscore descriptor phase vocabulary.
const fn protection_phase_text(phase: WatchdogProtectionPhase) -> &'static str {
    match phase {
        WatchdogProtectionPhase::Pending => "pending",
        WatchdogProtectionPhase::Starting => "starting",
        WatchdogProtectionPhase::Armed => "armed",
        WatchdogProtectionPhase::Disarmed => "disarmed",
    }
}

// Encodes bytes as deterministic lowercase hexadecimal text.
fn hex_encode(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

// Decodes bounded canonical lowercase hexadecimal descriptor text.
fn hex_decode(value: &str) -> Result<Vec<u8>, WatchdogError> {
    if value.is_empty() || value.len() % 2 != 0 || !lower_hex(value, value.len()) {
        return Err(controller_error(
            "controller registry snapshot descriptor is invalid",
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

// Converts one already-bounded lowercase hexadecimal digit.
fn hex_digit(value: u8) -> Result<u8, WatchdogError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(controller_error(
            "controller registry snapshot descriptor is invalid",
        )),
    }
}

// Parses one canonical positive decimal integer without leading zeroes.
fn parse_positive(value: &str, reason: &'static str) -> Result<u64, WatchdogError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(controller_error(reason));
    }
    let value = value.parse::<u64>().map_err(|_| controller_error(reason))?;
    if value == 0 {
        return Err(controller_error(reason));
    }
    Ok(value)
}

// Returns whether one identity is exact lowercase fixed-width hexadecimal text.
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Creates one stable redacted controller-registry failure.
const fn controller_error(reason: &'static str) -> WatchdogError {
    WatchdogError::provider("controller registry", reason)
}
