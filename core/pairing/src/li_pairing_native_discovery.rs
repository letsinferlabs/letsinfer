// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{
    DisplayName, NodeAddress, NodeId, PairingInviteId, Sha256Digest, UnixMilliseconds,
};

use crate::{
    PairingAdvertisement, PairingDiscoveryProvider, PairingError, PairingMode,
    PairingNativeCommand, PairingNativeCommandOutput, PairingNativeCommandRunner,
    PairingNativeProcess,
};

pub const PAIRING_DISCOVERY_PORT: u16 = 9_769;
pub const PAIRING_DISCOVERY_SERVICE_TYPE: &str = "_letsinfer._tcp";
pub const PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE: &str = "_letsinfer-candidate._tcp";

const DISCOVERY_DOMAIN: &str = "local";
const DISCOVERY_PROTOCOL: &str = "1";
const MAX_DISCOVERY_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_DISCOVERY_RECORDS: usize = 16;
const MAX_DISCOVERY_SECONDS: u8 = 15;
const MAX_TXT_VALUE_BYTES: usize = 200;
const PUBLISHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const PUBLISHER_STARTUP_TIMEOUT: Duration = Duration::from_millis(250);

// Selects the exact native DNS-SD command contract for one host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingDiscoveryPlatform {
    LinuxAvahi,
    MacosBonjour,
}

// Describes the public authorization hint without exposing ConnectX binding material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingDiscoveryMode {
    Lan,
    Remote,
    ConnectX,
}

// Returns one validated credential-free pairing discovery record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingDiscoveredAdvertisement {
    invite_id: PairingInviteId,
    display_name: DisplayName,
    address: NodeAddress,
    port: u16,
    certificate_fingerprint: Sha256Digest,
    expires_at: UnixMilliseconds,
    mode: PairingDiscoveryMode,
}

// Publishes only resident-owned identity fingerprints needed to pin candidate-offer preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingCandidateAdvertisement {
    node_id: NodeId,
    display_name: DisplayName,
    control_address: NodeAddress,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
    expires_at: UnixMilliseconds,
}

impl PairingCandidateAdvertisement {
    // Creates one credential-free candidate record whose owner controls its publication lifetime.
    pub fn new(
        node_id: NodeId,
        display_name: DisplayName,
        control_address: NodeAddress,
        public_key_sha256: Sha256Digest,
        certificate_sha256: Sha256Digest,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, PairingError> {
        if expires_at.value() == 0 {
            return Err(PairingError::InvalidRequest {
                reason: "candidate advertisement expiration is invalid",
            });
        }
        Ok(Self {
            node_id,
            display_name,
            control_address,
            public_key_sha256,
            certificate_sha256,
            expires_at,
        })
    }

    // Returns the exact local node offering enrollment.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the user-facing local node name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the private address served by the dedicated pairing listener.
    pub const fn control_address(&self) -> &NodeAddress {
        &self.control_address
    }

    // Returns the candidate public-key fingerprint required by ConnectX invitations.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the pairing TLS leaf fingerprint that must be pinned before preflight.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the exclusive advertisement expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }
}

// Returns one validated candidate advertisement discovered before ConnectX invitation creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingDiscoveredCandidate {
    node_id: NodeId,
    display_name: DisplayName,
    address: NodeAddress,
    port: u16,
    public_key_sha256: Sha256Digest,
    certificate_sha256: Sha256Digest,
    expires_at: UnixMilliseconds,
}

impl PairingDiscoveredCandidate {
    // Creates one complete candidate record accepted only on the dedicated pairing endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        display_name: DisplayName,
        address: NodeAddress,
        port: u16,
        public_key_sha256: Sha256Digest,
        certificate_sha256: Sha256Digest,
        expires_at: UnixMilliseconds,
    ) -> Result<Self, PairingError> {
        if port != PAIRING_DISCOVERY_PORT || expires_at.value() == 0 {
            return Err(PairingError::DiscoveryUnavailable);
        }
        Ok(Self {
            node_id,
            display_name,
            address,
            port,
            public_key_sha256,
            certificate_sha256,
            expires_at,
        })
    }

    // Returns the exact advertised candidate identity.
    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    // Returns the advertised candidate display name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the resolved candidate address.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the fixed dedicated pairing listener port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the candidate public-key fingerprint required by ConnectX authorization.
    pub const fn public_key_sha256(&self) -> &Sha256Digest {
        &self.public_key_sha256
    }

    // Returns the candidate TLS leaf fingerprint required before connection.
    pub const fn certificate_sha256(&self) -> &Sha256Digest {
        &self.certificate_sha256
    }

    // Returns the exclusive advertisement expiration boundary.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }
}

// Owns one continuously published candidate-offer discovery process.
pub struct NativePairingCandidateDiscoveryProvider {
    platform: PairingDiscoveryPlatform,
    publisher_executable: PathBuf,
    runner: Arc<dyn PairingNativeCommandRunner>,
    publication: Mutex<Option<Box<dyn PairingNativeProcess>>>,
}

impl NativePairingCandidateDiscoveryProvider {
    // Creates one inert candidate publisher from an explicit native executable.
    pub fn new(
        platform: PairingDiscoveryPlatform,
        publisher_executable: PathBuf,
        runner: Arc<dyn PairingNativeCommandRunner>,
    ) -> Result<Self, PairingError> {
        PairingNativeCommand::new(publisher_executable.clone(), Vec::new())?;
        Ok(Self {
            platform,
            publisher_executable,
            runner,
            publication: Mutex::new(None),
        })
    }

    // Starts exactly one candidate publication and rejects overlapping identity replacement.
    pub fn publish(
        &self,
        advertisement: &PairingCandidateAdvertisement,
    ) -> Result<(), PairingError> {
        let service_name = discovery_service_name(advertisement.display_name())?;
        let fields = candidate_publication_fields(advertisement)?;
        let mut arguments = match self.platform {
            PairingDiscoveryPlatform::LinuxAvahi => vec![
                service_name,
                PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE.to_string(),
                PAIRING_DISCOVERY_PORT.to_string(),
            ],
            PairingDiscoveryPlatform::MacosBonjour => vec![
                "-R".to_string(),
                service_name,
                PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE.to_string(),
                DISCOVERY_DOMAIN.to_string(),
                PAIRING_DISCOVERY_PORT.to_string(),
            ],
        };
        arguments.extend(fields);
        let command = PairingNativeCommand::new(self.publisher_executable.clone(), arguments)?;
        let mut process = self.runner.spawn(&command)?;
        process.require_running(PUBLISHER_STARTUP_TIMEOUT)?;
        let mut publication = self
            .publication
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?;
        if publication.is_some() {
            drop(publication);
            let _ = process.stop(PUBLISHER_SHUTDOWN_TIMEOUT);
            return Err(PairingError::DiscoveryUnavailable);
        }
        *publication = Some(process);
        Ok(())
    }

    // Stops the exact candidate publication idempotently.
    pub fn close(&self) -> Result<(), PairingError> {
        let process = self
            .publication
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?
            .take();
        let Some(mut process) = process else {
            return Ok(());
        };
        process.stop(PUBLISHER_SHUTDOWN_TIMEOUT)
    }
}

impl Drop for NativePairingCandidateDiscoveryProvider {
    // Retires the candidate publication when its resident owner stops.
    fn drop(&mut self) {
        if let Ok(publication) = self.publication.get_mut() {
            if let Some(mut process) = publication.take() {
                let _ = process.stop(PUBLISHER_SHUTDOWN_TIMEOUT);
            }
        }
    }
}

impl PairingDiscoveredAdvertisement {
    // Creates one complete invitation record accepted only on the dedicated pairing endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invite_id: PairingInviteId,
        display_name: DisplayName,
        address: NodeAddress,
        port: u16,
        certificate_fingerprint: Sha256Digest,
        expires_at: UnixMilliseconds,
        mode: PairingDiscoveryMode,
    ) -> Result<Self, PairingError> {
        if port != PAIRING_DISCOVERY_PORT || expires_at.value() == 0 {
            return Err(PairingError::DiscoveryUnavailable);
        }
        Ok(Self {
            invite_id,
            display_name,
            address,
            port,
            certificate_fingerprint,
            expires_at,
            mode,
        })
    }

    // Returns the one-use invitation identity.
    pub const fn invite_id(&self) -> &PairingInviteId {
        &self.invite_id
    }

    // Returns the advertised main-node name.
    pub const fn display_name(&self) -> &DisplayName {
        &self.display_name
    }

    // Returns the resolved DNS-SD host or numeric address.
    pub const fn address(&self) -> &NodeAddress {
        &self.address
    }

    // Returns the fixed private pairing listener port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    // Returns the certificate identity that the candidate must pin.
    pub const fn certificate_fingerprint(&self) -> &Sha256Digest {
        &self.certificate_fingerprint
    }

    // Returns when the one-use advertisement becomes unusable.
    pub const fn expires_at(&self) -> UnixMilliseconds {
        self.expires_at
    }

    // Returns the public authorization-mode hint.
    pub const fn mode(&self) -> PairingDiscoveryMode {
        self.mode
    }
}

// Publishes pairing windows with exact Avahi or Bonjour argv and owns their cleanup.
pub struct NativePairingDiscoveryProvider {
    platform: PairingDiscoveryPlatform,
    publisher_executable: PathBuf,
    runner: Arc<dyn PairingNativeCommandRunner>,
    publications: Mutex<BTreeMap<String, Box<dyn PairingNativeProcess>>>,
}

impl NativePairingDiscoveryProvider {
    // Creates one native publisher from a composition-root supplied executable.
    pub fn new(
        platform: PairingDiscoveryPlatform,
        publisher_executable: PathBuf,
        runner: Arc<dyn PairingNativeCommandRunner>,
    ) -> Result<Self, PairingError> {
        PairingNativeCommand::new(publisher_executable.clone(), Vec::new())?;
        Ok(Self {
            platform,
            publisher_executable,
            runner,
            publications: Mutex::new(BTreeMap::new()),
        })
    }

    // Stops one exact invitation publisher and reports bounded cleanup failure.
    pub fn close(&self, invite_id: &PairingInviteId) -> Result<(), PairingError> {
        let process = self
            .publications
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?
            .remove(invite_id.as_str());
        let Some(mut process) = process else {
            return Ok(());
        };
        process.stop(PUBLISHER_SHUTDOWN_TIMEOUT)
    }

    // Returns the number of publishers still owned by this provider.
    pub fn active_publication_count(&self) -> Result<usize, PairingError> {
        self.publications
            .lock()
            .map(|values| values.len())
            .map_err(|_| PairingError::StateUnavailable)
    }

    // Builds one platform command from the closed public pairing fields.
    fn publisher_command(
        &self,
        advertisement: &PairingAdvertisement,
    ) -> Result<PairingNativeCommand, PairingError> {
        let service_name = discovery_service_name(advertisement.display_name())?;
        let fields = publication_fields(advertisement)?;
        let mut arguments = match self.platform {
            PairingDiscoveryPlatform::LinuxAvahi => vec![
                service_name,
                PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
                PAIRING_DISCOVERY_PORT.to_string(),
            ],
            PairingDiscoveryPlatform::MacosBonjour => vec![
                "-R".to_string(),
                service_name,
                PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
                DISCOVERY_DOMAIN.to_string(),
                PAIRING_DISCOVERY_PORT.to_string(),
            ],
        };
        arguments.extend(fields);
        PairingNativeCommand::new(self.publisher_executable.clone(), arguments)
    }
}

impl PairingDiscoveryProvider for NativePairingDiscoveryProvider {
    // Starts one publisher, proves startup, and retains its exact process owner.
    fn publish(&self, advertisement: &PairingAdvertisement) -> Result<(), PairingError> {
        let command = self.publisher_command(advertisement)?;
        let mut process = self.runner.spawn(&command)?;
        process.require_running(PUBLISHER_STARTUP_TIMEOUT)?;
        let mut publications = self
            .publications
            .lock()
            .map_err(|_| PairingError::StateUnavailable)?;
        if publications.contains_key(advertisement.invite_id().as_str()) {
            drop(publications);
            let _ = process.stop(PUBLISHER_SHUTDOWN_TIMEOUT);
            return Err(PairingError::DiscoveryUnavailable);
        }
        publications.insert(advertisement.invite_id().as_str().to_string(), process);
        Ok(())
    }

    // Removes only the exact invitation publisher and keeps cleanup best-effort at drop boundaries.
    fn unpublish(&self, invite_id: &PairingInviteId) {
        let _ = self.close(invite_id);
    }
}

impl Drop for NativePairingDiscoveryProvider {
    // Retires every still-owned publisher when its composition owner stops.
    fn drop(&mut self) {
        if let Ok(mut publications) = self.publications.lock() {
            for (_, mut process) in std::mem::take(&mut *publications) {
                let _ = process.stop(PUBLISHER_SHUTDOWN_TIMEOUT);
            }
        }
    }
}

// Browses and validates credential-free advertisements through native DNS-SD commands.
pub struct NativePairingDiscoveryBrowser {
    platform: PairingDiscoveryPlatform,
    browser_executable: PathBuf,
    runner: Arc<dyn PairingNativeCommandRunner>,
}

impl NativePairingDiscoveryBrowser {
    // Creates one browser without discovering executables inside the provider.
    pub fn new(
        platform: PairingDiscoveryPlatform,
        browser_executable: PathBuf,
        runner: Arc<dyn PairingNativeCommandRunner>,
    ) -> Result<Self, PairingError> {
        PairingNativeCommand::new(browser_executable.clone(), Vec::new())?;
        Ok(Self {
            platform,
            browser_executable,
            runner,
        })
    }

    // Runs one bounded native browse and returns only complete non-conflicting records.
    pub fn browse(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredAdvertisement>, PairingError> {
        if !(1..=MAX_DISCOVERY_SECONDS).contains(&timeout_seconds) {
            return Err(PairingError::InvalidRequest {
                reason: "pairing discovery timeout must be between 1 and 15 seconds",
            });
        }
        match self.platform {
            PairingDiscoveryPlatform::LinuxAvahi => self.browse_avahi(timeout_seconds),
            PairingDiscoveryPlatform::MacosBonjour => self.browse_bonjour(timeout_seconds),
        }
    }

    // Runs one Avahi resolver/browser command and parses its machine-oriented output.
    fn browse_avahi(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredAdvertisement>, PairingError> {
        let command = PairingNativeCommand::new(
            self.browser_executable.clone(),
            vec![
                "-rpt".to_string(),
                PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
            ],
        )?;
        let output = self.runner.run(
            &command,
            Duration::from_secs(u64::from(timeout_seconds)),
            MAX_DISCOVERY_OUTPUT_BYTES,
        )?;
        require_browse_result(&output, true)?;
        parse_avahi_advertisements(output.stdout())
    }

    // Runs Bonjour browse plus bounded resolve commands for each advertised service.
    fn browse_bonjour(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredAdvertisement>, PairingError> {
        let browse = PairingNativeCommand::new(
            self.browser_executable.clone(),
            vec![
                "-B".to_string(),
                PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
                DISCOVERY_DOMAIN.to_string(),
            ],
        )?;
        let output = self.runner.run(
            &browse,
            Duration::from_secs(u64::from(timeout_seconds)),
            MAX_DISCOVERY_OUTPUT_BYTES,
        )?;
        require_browse_result(&output, false)?;
        let instances = parse_bonjour_instances(output.stdout())?;
        let mut records = Vec::with_capacity(instances.len());
        for instance in instances {
            let resolve = PairingNativeCommand::new(
                self.browser_executable.clone(),
                vec![
                    "-L".to_string(),
                    instance.clone(),
                    PAIRING_DISCOVERY_SERVICE_TYPE.to_string(),
                    DISCOVERY_DOMAIN.to_string(),
                ],
            )?;
            let output = self.runner.run(
                &resolve,
                Duration::from_secs(1),
                MAX_DISCOVERY_OUTPUT_BYTES / MAX_DISCOVERY_RECORDS,
            )?;
            require_browse_result(&output, false)?;
            if let Some(record) = parse_bonjour_advertisement(&instance, output.stdout())? {
                records.push(record);
            }
        }
        normalized_records(records)
    }

    // Runs one bounded native browse for candidate-offer advertisements only.
    pub fn browse_candidates(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredCandidate>, PairingError> {
        if !(1..=MAX_DISCOVERY_SECONDS).contains(&timeout_seconds) {
            return Err(PairingError::InvalidRequest {
                reason: "pairing discovery timeout must be between 1 and 15 seconds",
            });
        }
        match self.platform {
            PairingDiscoveryPlatform::LinuxAvahi => self.browse_avahi_candidates(timeout_seconds),
            PairingDiscoveryPlatform::MacosBonjour => {
                self.browse_bonjour_candidates(timeout_seconds)
            }
        }
    }

    // Runs one Avahi candidate browse and parses only the dedicated service type.
    fn browse_avahi_candidates(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredCandidate>, PairingError> {
        let command = PairingNativeCommand::new(
            self.browser_executable.clone(),
            vec![
                "-rpt".to_string(),
                PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE.to_string(),
            ],
        )?;
        let output = self.runner.run(
            &command,
            Duration::from_secs(u64::from(timeout_seconds)),
            MAX_DISCOVERY_OUTPUT_BYTES,
        )?;
        require_browse_result(&output, true)?;
        parse_avahi_candidates(output.stdout())
    }

    // Runs one Bonjour candidate browse plus bounded resolve for each result.
    fn browse_bonjour_candidates(
        &self,
        timeout_seconds: u8,
    ) -> Result<Vec<PairingDiscoveredCandidate>, PairingError> {
        let browse = PairingNativeCommand::new(
            self.browser_executable.clone(),
            vec![
                "-B".to_string(),
                PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE.to_string(),
                DISCOVERY_DOMAIN.to_string(),
            ],
        )?;
        let output = self.runner.run(
            &browse,
            Duration::from_secs(u64::from(timeout_seconds)),
            MAX_DISCOVERY_OUTPUT_BYTES,
        )?;
        require_browse_result(&output, false)?;
        let instances =
            parse_bonjour_instances_for(output.stdout(), PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE)?;
        let mut records = Vec::with_capacity(instances.len());
        for instance in instances {
            let resolve = PairingNativeCommand::new(
                self.browser_executable.clone(),
                vec![
                    "-L".to_string(),
                    instance.clone(),
                    PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE.to_string(),
                    DISCOVERY_DOMAIN.to_string(),
                ],
            )?;
            let output = self.runner.run(
                &resolve,
                Duration::from_secs(1),
                MAX_DISCOVERY_OUTPUT_BYTES / MAX_DISCOVERY_RECORDS,
            )?;
            require_browse_result(&output, false)?;
            if let Some(record) = parse_bonjour_candidate(&instance, output.stdout())? {
                records.push(record);
            }
        }
        normalized_candidates(records)
    }
}

// Returns a bounded user-facing DNS-SD instance name.
fn discovery_service_name(display_name: &DisplayName) -> Result<String, PairingError> {
    let name = format!("Let's Infer — {}", display_name.as_str());
    validate_txt_value(&name)?;
    Ok(name)
}

// Projects one advertisement into a sorted credential-free TXT record.
fn publication_fields(advertisement: &PairingAdvertisement) -> Result<Vec<String>, PairingError> {
    let values = BTreeMap::from([
        ("expires", advertisement.expires_at().value().to_string()),
        ("invite", advertisement.invite_id().as_str().to_string()),
        (
            "mode",
            discovery_mode_name(advertisement.mode()).to_string(),
        ),
        ("protocol", DISCOVERY_PROTOCOL.to_string()),
        (
            "tls",
            advertisement.certificate_fingerprint().as_str().to_string(),
        ),
    ]);
    values
        .into_iter()
        .map(|(name, value)| {
            validate_txt_value(name)?;
            validate_txt_value(&value)?;
            Ok(format!("{name}={value}"))
        })
        .collect()
}

// Projects one candidate advertisement into sorted credential-free TXT fields.
fn candidate_publication_fields(
    advertisement: &PairingCandidateAdvertisement,
) -> Result<Vec<String>, PairingError> {
    let values = BTreeMap::from([
        ("candidate", advertisement.node_id().as_str().to_string()),
        ("expires", advertisement.expires_at().value().to_string()),
        (
            "key",
            advertisement.public_key_sha256().as_str().to_string(),
        ),
        ("protocol", DISCOVERY_PROTOCOL.to_string()),
        (
            "tls",
            advertisement.certificate_sha256().as_str().to_string(),
        ),
    ]);
    values
        .into_iter()
        .map(|(name, value)| {
            validate_txt_value(name)?;
            validate_txt_value(&value)?;
            Ok(format!("{name}={value}"))
        })
        .collect()
}

// Returns the public mode name without ConnectX interface or candidate identity.
const fn discovery_mode_name(mode: &PairingMode) -> &'static str {
    match mode {
        PairingMode::Lan => "lan",
        PairingMode::Remote => "remote",
        PairingMode::ConnectX { .. } => "connectx",
    }
}

// Accepts ordinary completion or a deadline-ended streaming browse.
fn require_browse_result(
    output: &PairingNativeCommandOutput,
    accepts_avahi_timeout_status: bool,
) -> Result<(), PairingError> {
    if output.timed_out()
        || output.status() == 0
        || (accepts_avahi_timeout_status && output.status() == 124)
    {
        return Ok(());
    }
    Err(PairingError::DiscoveryUnavailable)
}

// Parses bounded Avahi resolve records and chooses one stable address per invitation.
fn parse_avahi_advertisements(
    output: &[u8],
) -> Result<Vec<PairingDiscoveredAdvertisement>, PairingError> {
    let text = std::str::from_utf8(output).map_err(|_| PairingError::DiscoveryUnavailable)?;
    let mut records = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(';').collect();
        if fields.len() < 10 || fields[0] != "=" || fields[4] != PAIRING_DISCOVERY_SERVICE_TYPE {
            continue;
        }
        let port = fields[8]
            .parse::<u16>()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        let instance = decode_avahi_text(fields[3])?;
        let address = canonical_ip_address(fields[7])?;
        let Some(txt) = parse_txt_tokens(&fields[9..].join(" "))? else {
            continue;
        };
        records.push(discovered_record(&instance, &address, port, txt)?);
        if records.len() > MAX_DISCOVERY_RECORDS {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    normalized_records(records)
}

// Decodes Avahi backslash and decimal-byte escapes into strict UTF-8.
fn decode_avahi_text(value: &str) -> Result<String, PairingError> {
    let mut bytes = Vec::with_capacity(value.len());
    let value = value.as_bytes();
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            bytes.push(value[index]);
            index += 1;
            continue;
        }
        if index + 1 >= value.len() {
            return Err(PairingError::DiscoveryUnavailable);
        }
        if index + 3 < value.len() && value[index + 1..index + 4].iter().all(u8::is_ascii_digit) {
            let number = std::str::from_utf8(&value[index + 1..index + 4])
                .map_err(|_| PairingError::DiscoveryUnavailable)?
                .parse::<u16>()
                .map_err(|_| PairingError::DiscoveryUnavailable)?;
            bytes.push(u8::try_from(number).map_err(|_| PairingError::DiscoveryUnavailable)?);
            index += 4;
            continue;
        }
        let escaped = value[index + 1];
        if escaped.is_ascii_control() {
            return Err(PairingError::DiscoveryUnavailable);
        }
        bytes.push(escaped);
        index += 2;
    }
    String::from_utf8(bytes).map_err(|_| PairingError::DiscoveryUnavailable)
}

// Extracts unique Bonjour instance names from one bounded browse transcript.
fn parse_bonjour_instances(output: &[u8]) -> Result<Vec<String>, PairingError> {
    parse_bonjour_instances_for(output, PAIRING_DISCOVERY_SERVICE_TYPE)
}

// Extracts unique Bonjour instances for one exact service type.
fn parse_bonjour_instances_for(
    output: &[u8],
    service_type: &str,
) -> Result<Vec<String>, PairingError> {
    let text = std::str::from_utf8(output).map_err(|_| PairingError::DiscoveryUnavailable)?;
    let mut instances = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(action) = fields.iter().position(|value| *value == "Add") else {
            continue;
        };
        if action + 5 >= fields.len()
            || fields[action + 3].trim_end_matches('.') != DISCOVERY_DOMAIN
            || fields[action + 4].trim_end_matches('.') != service_type
        {
            continue;
        }
        let instance = fields[action + 5..].join(" ");
        validate_txt_value(&instance)?;
        instances.insert(instance);
        if instances.len() > MAX_DISCOVERY_RECORDS {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    Ok(instances.into_iter().collect())
}

// Parses bounded Avahi candidate resolve records and chooses one stable record per node.
fn parse_avahi_candidates(output: &[u8]) -> Result<Vec<PairingDiscoveredCandidate>, PairingError> {
    let text = std::str::from_utf8(output).map_err(|_| PairingError::DiscoveryUnavailable)?;
    let mut records = Vec::new();
    for line in text.lines() {
        let fields = line.split(';').collect::<Vec<_>>();
        if fields.len() < 10
            || fields[0] != "="
            || fields[4] != PAIRING_CANDIDATE_DISCOVERY_SERVICE_TYPE
        {
            continue;
        }
        let port = fields[8]
            .parse::<u16>()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        let instance = decode_avahi_text(fields[3])?;
        let address = canonical_ip_address(fields[7])?;
        let Some(txt) = parse_candidate_txt_tokens(&fields[9..].join(" "))? else {
            continue;
        };
        records.push(discovered_candidate(&instance, &address, port, txt)?);
        if records.len() > MAX_DISCOVERY_RECORDS {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    normalized_candidates(records)
}

// Parses one Bonjour candidate resolve transcript into the shared candidate shape.
fn parse_bonjour_candidate(
    instance: &str,
    output: &[u8],
) -> Result<Option<PairingDiscoveredCandidate>, PairingError> {
    let text = std::str::from_utf8(output).map_err(|_| PairingError::DiscoveryUnavailable)?;
    let mut endpoint = None;
    for line in text.lines() {
        let Some((_, remainder)) = line.split_once(" can be reached at ") else {
            continue;
        };
        let target = remainder
            .split_whitespace()
            .next()
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let (host, port) = target
            .rsplit_once(':')
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let host = host.trim_matches(['[', ']']).trim_end_matches('.');
        let port = port
            .parse::<u16>()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        if endpoint.replace((host.to_string(), port)).is_some() {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    let (host, port) = endpoint.ok_or(PairingError::DiscoveryUnavailable)?;
    let Some(txt) = parse_candidate_txt_tokens(text)? else {
        return Ok(None);
    };
    discovered_candidate(instance, &host, port, txt).map(Some)
}

// Parses candidate TXT values while ignoring pairing invitations and unrelated services.
fn parse_candidate_txt_tokens(
    value: &str,
) -> Result<Option<BTreeMap<String, String>>, PairingError> {
    let tokens = txt_tokens(value)?;
    if !tokens.iter().any(|token| {
        token
            .split_once('=')
            .is_some_and(|(name, _)| name == "candidate")
    }) {
        return Ok(None);
    }
    let expected = BTreeSet::from(["candidate", "expires", "key", "protocol", "tls"]);
    let mut fields = BTreeMap::new();
    for token in tokens {
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if !expected.contains(name) {
            return Err(PairingError::DiscoveryUnavailable);
        }
        validate_txt_value(name)?;
        validate_txt_value(value)?;
        if fields.insert(name.to_string(), value.to_string()).is_some() {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    if fields.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(PairingError::DiscoveryUnavailable);
    }
    Ok(Some(fields))
}

// Tokenizes one TXT transcript while preserving quoted service values.
fn txt_tokens(value: &str) -> Result<Vec<String>, PairingError> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for character in value.chars() {
        match character {
            '"' => quoted = !quoted,
            character if character.is_whitespace() && !quoted => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            character => token.push(character),
        }
    }
    if quoted {
        return Err(PairingError::DiscoveryUnavailable);
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

// Constructs one validated discovered candidate from exact public TXT fields.
fn discovered_candidate(
    instance: &str,
    address: &str,
    port: u16,
    fields: BTreeMap<String, String>,
) -> Result<PairingDiscoveredCandidate, PairingError> {
    if port != PAIRING_DISCOVERY_PORT
        || fields.get("protocol").map(String::as_str) != Some(DISCOVERY_PROTOCOL)
    {
        return Err(PairingError::DiscoveryUnavailable);
    }
    Ok(PairingDiscoveredCandidate {
        node_id: NodeId::parse(
            fields
                .get("candidate")
                .ok_or(PairingError::DiscoveryUnavailable)?,
        )?,
        display_name: normalized_service_display_name(instance)?,
        address: NodeAddress::parse(address)?,
        port,
        public_key_sha256: Sha256Digest::parse(
            fields
                .get("key")
                .ok_or(PairingError::DiscoveryUnavailable)?,
        )?,
        certificate_sha256: Sha256Digest::parse(
            fields
                .get("tls")
                .ok_or(PairingError::DiscoveryUnavailable)?,
        )?,
        expires_at: UnixMilliseconds::new(
            fields
                .get("expires")
                .ok_or(PairingError::DiscoveryUnavailable)?
                .parse::<u64>()
                .map_err(|_| PairingError::DiscoveryUnavailable)?,
        ),
    })
}

// Sorts candidates and rejects conflicting duplicates for one node identity.
fn normalized_candidates(
    mut records: Vec<PairingDiscoveredCandidate>,
) -> Result<Vec<PairingDiscoveredCandidate>, PairingError> {
    records.sort_by(|left, right| {
        left.node_id()
            .as_str()
            .cmp(right.node_id().as_str())
            .then_with(|| left.address().as_str().cmp(right.address().as_str()))
    });
    let mut normalized = Vec::<PairingDiscoveredCandidate>::new();
    for record in records {
        if let Some(previous) = normalized.last() {
            if previous.node_id() == record.node_id() {
                if previous == &record {
                    continue;
                }
                return Err(PairingError::DiscoveryUnavailable);
            }
        }
        normalized.push(record);
    }
    Ok(normalized)
}

// Parses one Bonjour resolve transcript into the shared discovery shape.
fn parse_bonjour_advertisement(
    instance: &str,
    output: &[u8],
) -> Result<Option<PairingDiscoveredAdvertisement>, PairingError> {
    let text = std::str::from_utf8(output).map_err(|_| PairingError::DiscoveryUnavailable)?;
    let mut endpoint = None;
    for line in text.lines() {
        let Some((_, remainder)) = line.split_once(" can be reached at ") else {
            continue;
        };
        let target = remainder
            .split_whitespace()
            .next()
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let (host, port) = target
            .rsplit_once(':')
            .ok_or(PairingError::DiscoveryUnavailable)?;
        let host = host.trim_matches(['[', ']']).trim_end_matches('.');
        let port = port
            .parse::<u16>()
            .map_err(|_| PairingError::DiscoveryUnavailable)?;
        if endpoint.replace((host.to_string(), port)).is_some() {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    let (host, port) = endpoint.ok_or(PairingError::DiscoveryUnavailable)?;
    let Some(txt) = parse_txt_tokens(text)? else {
        return Ok(None);
    };
    discovered_record(instance, &host, port, txt).map(Some)
}

// Parses pairing-window TXT values while ignoring established non-invitation node records.
fn parse_txt_tokens(value: &str) -> Result<Option<BTreeMap<String, String>>, PairingError> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for character in value.chars() {
        match character {
            '"' => quoted = !quoted,
            character if character.is_whitespace() && !quoted => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            character => token.push(character),
        }
    }
    if quoted {
        return Err(PairingError::DiscoveryUnavailable);
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    let is_pairing_window = tokens.iter().any(|token| {
        token
            .split_once('=')
            .is_some_and(|(name, _)| name == "invite")
    });
    if !is_pairing_window {
        return Ok(None);
    }
    let expected = BTreeSet::from(["expires", "invite", "mode", "protocol", "tls"]);
    let mut fields = BTreeMap::new();
    for token in tokens {
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if !expected.contains(name) {
            return Err(PairingError::DiscoveryUnavailable);
        }
        validate_txt_value(name)?;
        validate_txt_value(value)?;
        if fields.insert(name.to_string(), value.to_string()).is_some() {
            return Err(PairingError::DiscoveryUnavailable);
        }
    }
    if fields.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(PairingError::DiscoveryUnavailable);
    }
    Ok(Some(fields))
}

// Constructs one validated discovery record from exact public TXT fields.
fn discovered_record(
    instance: &str,
    address: &str,
    port: u16,
    fields: BTreeMap<String, String>,
) -> Result<PairingDiscoveredAdvertisement, PairingError> {
    if port != PAIRING_DISCOVERY_PORT
        || fields.get("protocol").map(String::as_str) != Some(DISCOVERY_PROTOCOL)
    {
        return Err(PairingError::DiscoveryUnavailable);
    }
    let display_name = normalized_service_display_name(instance)?;
    let invite_id = PairingInviteId::parse(
        fields
            .get("invite")
            .ok_or(PairingError::DiscoveryUnavailable)?,
    )?;
    let certificate_fingerprint = Sha256Digest::parse(
        fields
            .get("tls")
            .ok_or(PairingError::DiscoveryUnavailable)?,
    )?;
    let expires_at = fields
        .get("expires")
        .ok_or(PairingError::DiscoveryUnavailable)?
        .parse::<u64>()
        .map(UnixMilliseconds::new)
        .map_err(|_| PairingError::DiscoveryUnavailable)?;
    if expires_at.value() == 0 {
        return Err(PairingError::DiscoveryUnavailable);
    }
    let mode = match fields.get("mode").map(String::as_str) {
        Some("lan") => PairingDiscoveryMode::Lan,
        Some("remote") => PairingDiscoveryMode::Remote,
        Some("connectx") => PairingDiscoveryMode::ConnectX,
        _ => return Err(PairingError::DiscoveryUnavailable),
    };
    Ok(PairingDiscoveredAdvertisement {
        invite_id,
        display_name,
        address: NodeAddress::parse(address)?,
        port,
        certificate_fingerprint,
        expires_at,
        mode,
    })
}

// Removes the product prefix and native collision suffix from one service name.
fn normalized_service_display_name(instance: &str) -> Result<DisplayName, PairingError> {
    let value = instance
        .strip_prefix("Let's Infer — ")
        .unwrap_or(instance)
        .trim();
    let value = value
        .rsplit_once(" #")
        .filter(|(_, suffix)| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map_or(value, |(name, _)| name.trim());
    DisplayName::parse(value).map_err(Into::into)
}

// Canonicalizes one numeric Avahi address before record comparison.
fn canonical_ip_address(value: &str) -> Result<String, PairingError> {
    IpAddr::from_str(value)
        .map(|address| address.to_string())
        .map_err(|_| PairingError::DiscoveryUnavailable)
}

// Deduplicates one invitation across address families and rejects identity conflicts.
fn normalized_records(
    records: Vec<PairingDiscoveredAdvertisement>,
) -> Result<Vec<PairingDiscoveredAdvertisement>, PairingError> {
    let mut normalized: BTreeMap<String, PairingDiscoveredAdvertisement> = BTreeMap::new();
    for record in records {
        let key = record.invite_id().as_str().to_string();
        if let Some(previous) = normalized.get(&key) {
            if !same_discovery_identity(previous, &record) {
                return Err(PairingError::DiscoveryUnavailable);
            }
            if address_rank(record.address()) >= address_rank(previous.address()) {
                continue;
            }
        }
        normalized.insert(key, record);
    }
    let mut records: Vec<_> = normalized.into_values().collect();
    records.sort_by(|left, right| {
        left.display_name()
            .as_str()
            .to_lowercase()
            .cmp(&right.display_name().as_str().to_lowercase())
            .then_with(|| left.invite_id().as_str().cmp(right.invite_id().as_str()))
    });
    Ok(records)
}

// Compares immutable discovery identity while allowing address-family duplicates.
fn same_discovery_identity(
    left: &PairingDiscoveredAdvertisement,
    right: &PairingDiscoveredAdvertisement,
) -> bool {
    left.invite_id() == right.invite_id()
        && left.display_name() == right.display_name()
        && left.port() == right.port()
        && left.certificate_fingerprint() == right.certificate_fingerprint()
        && left.expires_at() == right.expires_at()
        && left.mode() == right.mode()
}

// Ranks stable LAN IPv4 before IPv6, link-local, loopback, and unresolved hosts.
fn address_rank(address: &NodeAddress) -> (u8, Vec<u8>) {
    let Ok(address) = IpAddr::from_str(address.as_str()) else {
        return (5, address.as_str().as_bytes().to_vec());
    };
    match address {
        IpAddr::V4(value) if value.is_loopback() => (4, value.octets().to_vec()),
        IpAddr::V6(value) if value.is_loopback() => (4, value.octets().to_vec()),
        IpAddr::V4(value) if value.is_link_local() => (2, value.octets().to_vec()),
        IpAddr::V6(value) if value.is_unicast_link_local() => (3, value.octets().to_vec()),
        IpAddr::V4(value) => (0, value.octets().to_vec()),
        IpAddr::V6(value) => (1, value.octets().to_vec()),
    }
}

// Rejects empty, control-bearing, assignment-bearing, or oversized public TXT values.
fn validate_txt_value(value: &str) -> Result<(), PairingError> {
    if value.is_empty()
        || value.len() > MAX_TXT_VALUE_BYTES
        || value.contains('=')
        || value.chars().any(char::is_control)
    {
        return Err(PairingError::DiscoveryUnavailable);
    }
    Ok(())
}
