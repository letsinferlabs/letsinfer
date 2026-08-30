// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::fill;
use li_core_interface::{
    Accelerator, BootId, ByteCount, HardwareObservation, HardwareObservationId,
    InterconnectObservation, NodeId, PlatformIdentity, ProcessorObservation, UnixMilliseconds,
};

mod li_hardware_native;
mod li_hardware_observation_document;
mod li_linux_hardware_provider;
mod li_macos_hardware_provider;

pub use li_hardware_native::{HardwareCommandWait, HardwareNativeIo, SystemHardwareNativeIo};
pub use li_hardware_observation_document::{
    decode_hardware_observation, encode_hardware_observation,
};
pub use li_linux_hardware_provider::{LinuxHardwareConfiguration, LinuxHardwareProvider};
pub use li_macos_hardware_provider::{MacOsHardwareConfiguration, MacOsHardwareProvider};

// Describes one stable hardware observation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwareError {
    Interface(li_core_interface::InterfaceError),
    ProviderUnavailable,
    InvalidObservation { reason: &'static str },
    IdentityUnavailable,
    ClockUnavailable,
    PlatformMismatch,
    StateUnavailable,
}

impl fmt::Display for HardwareError {
    // Presents stable hardware language without leaking native command output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(error) => write!(formatter, "{error}"),
            Self::ProviderUnavailable => formatter.write_str("hardware provider is unavailable"),
            Self::InvalidObservation { reason } => {
                write!(formatter, "hardware observation is invalid: {reason}")
            }
            Self::IdentityUnavailable => {
                formatter.write_str("hardware observation identity is unavailable")
            }
            Self::ClockUnavailable => {
                formatter.write_str("hardware observation clock is unavailable")
            }
            Self::PlatformMismatch => {
                formatter.write_str("hardware provider returned a different platform")
            }
            Self::StateUnavailable => formatter.write_str("hardware manager state is unavailable"),
        }
    }
}

impl Error for HardwareError {}

impl From<li_core_interface::InterfaceError> for HardwareError {
    // Preserves one shared interface failure at the hardware boundary.
    fn from(error: li_core_interface::InterfaceError) -> Self {
        Self::Interface(error)
    }
}

// Carries platform and device facts from one provider observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareSnapshot {
    boot_id: BootId,
    platform: PlatformIdentity,
    processor: ProcessorObservation,
    memory_bytes: ByteCount,
    accelerators: Vec<Accelerator>,
    interconnects: Vec<InterconnectObservation>,
}

impl HardwareSnapshot {
    // Creates one provider snapshot without assigning node, identity, or time.
    pub const fn new(
        boot_id: BootId,
        platform: PlatformIdentity,
        processor: ProcessorObservation,
        memory_bytes: ByteCount,
        accelerators: Vec<Accelerator>,
        interconnects: Vec<InterconnectObservation>,
    ) -> Self {
        Self {
            boot_id,
            platform,
            processor,
            memory_bytes,
            accelerators,
            interconnects,
        }
    }

    // Returns the boot identity scoping mutable topology.
    pub const fn boot_id(&self) -> &BootId {
        &self.boot_id
    }

    // Returns the observed platform identity.
    pub const fn platform(&self) -> PlatformIdentity {
        self.platform
    }

    // Returns the observed processor facts.
    pub const fn processor(&self) -> &ProcessorObservation {
        &self.processor
    }

    // Returns observed host memory capacity.
    pub const fn memory_bytes(&self) -> ByteCount {
        self.memory_bytes
    }

    // Returns every physical accelerator observation.
    pub fn accelerators(&self) -> &[Accelerator] {
        &self.accelerators
    }

    // Returns every mutable topology link observation.
    pub fn interconnects(&self) -> &[InterconnectObservation] {
        &self.interconnects
    }
}

// Defines one platform or device-specific observation implementation.
pub trait HardwareProvider: Send + Sync {
    // Returns the exact platform this provider implements.
    fn platform(&self) -> PlatformIdentity;

    // Observes current platform, device, telemetry, and topology facts.
    fn observe(&self) -> Result<HardwareSnapshot, HardwareError>;
}

// Supplies unique observation identities explicitly.
pub trait HardwareIdentityProvider: Send + Sync {
    // Returns one new canonical hardware-observation identity.
    fn observation_id(&self) -> Result<HardwareObservationId, HardwareError>;
}

// Uses the operating-system CSPRNG for production observation identities.
#[derive(Default)]
pub struct SystemHardwareIdentityProvider;

impl HardwareIdentityProvider for SystemHardwareIdentityProvider {
    // Returns one random 128-bit observation identity.
    fn observation_id(&self) -> Result<HardwareObservationId, HardwareError> {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes).map_err(|_| HardwareError::IdentityUnavailable)?;
        HardwareObservationId::parse(&hexadecimal(&bytes)).map_err(Into::into)
    }
}

// Supplies observation time explicitly for production and tests.
pub trait HardwareClock: Send + Sync {
    // Returns current Unix time in milliseconds.
    fn now(&self) -> Result<UnixMilliseconds, HardwareError>;
}

// Reads production hardware time from the active host.
#[derive(Default)]
pub struct SystemHardwareClock;

impl HardwareClock for SystemHardwareClock {
    // Returns current host time without accepting a pre-epoch clock.
    fn now(&self) -> Result<UnixMilliseconds, HardwareError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HardwareError::ClockUnavailable)?;
        let milliseconds =
            u64::try_from(duration.as_millis()).map_err(|_| HardwareError::ClockUnavailable)?;
        Ok(UnixMilliseconds::new(milliseconds))
    }
}

// Describes whether one observation established or changed semantic facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwareEvent {
    HardwareObserved {
        observation_id: HardwareObservationId,
    },
    HardwareChanged {
        previous_observation_id: HardwareObservationId,
        observation_id: HardwareObservationId,
    },
    HardwareRefreshed {
        observation_id: HardwareObservationId,
    },
}

// Returns one validated hardware observation and its completed event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareChange {
    observation: HardwareObservation,
    event: HardwareEvent,
}

// Classifies one latest observation against an explicit caller-supplied age bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareObservationFreshness {
    Current,
    Stale { age_milliseconds: u64 },
}

// Returns one boot-scoped latest observation with explicit freshness semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareLatestObservation {
    observation: HardwareObservation,
    freshness: HardwareObservationFreshness,
}

impl HardwareLatestObservation {
    // Creates one latest observation only after reference-time classification succeeds.
    const fn new(
        observation: HardwareObservation,
        freshness: HardwareObservationFreshness,
    ) -> Self {
        Self {
            observation,
            freshness,
        }
    }

    // Returns the exact observation identity, boot scope, facts, and observation time.
    pub const fn observation(&self) -> &HardwareObservation {
        &self.observation
    }

    // Returns whether the observation remains within the caller's explicit age bound.
    pub const fn freshness(&self) -> HardwareObservationFreshness {
        self.freshness
    }
}

impl HardwareChange {
    // Creates one completed manager result.
    const fn new(observation: HardwareObservation, event: HardwareEvent) -> Self {
        Self { observation, event }
    }

    // Returns the validated hardware observation.
    pub const fn observation(&self) -> &HardwareObservation {
        &self.observation
    }

    // Returns the completed hardware event.
    pub const fn event(&self) -> &HardwareEvent {
        &self.event
    }
}

// Owns refreshable hardware observations while providers only observe mechanisms.
pub struct HardwareManager {
    node_id: NodeId,
    provider: Arc<dyn HardwareProvider>,
    identity: Arc<dyn HardwareIdentityProvider>,
    clock: Arc<dyn HardwareClock>,
    latest: Mutex<Option<(HardwareSnapshot, HardwareObservation)>>,
}

impl HardwareManager {
    // Creates one manager from explicit node, provider, identity, and clock inputs.
    pub fn new(
        node_id: NodeId,
        provider: Arc<dyn HardwareProvider>,
        identity: Arc<dyn HardwareIdentityProvider>,
        clock: Arc<dyn HardwareClock>,
    ) -> Self {
        Self {
            node_id,
            provider,
            identity,
            clock,
            latest: Mutex::new(None),
        }
    }

    // Observes, validates, and classifies one current hardware snapshot.
    pub fn observe(&self) -> Result<HardwareChange, HardwareError> {
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| HardwareError::StateUnavailable)?;
        let snapshot = self.provider.observe()?;
        if snapshot.platform() != self.provider.platform() {
            return Err(HardwareError::PlatformMismatch);
        }
        let observation_id = self.identity.observation_id()?;
        let observed_at = self.clock.now()?;
        if latest.as_ref().is_some_and(|(_, previous)| {
            previous.observation_id() == &observation_id
                || previous.observed_at().value() > observed_at.value()
        }) {
            return Err(HardwareError::InvalidObservation {
                reason: "hardware observation identity or time did not advance",
            });
        }
        let observation = HardwareObservation::new(
            observation_id,
            self.node_id.clone(),
            snapshot.boot_id().clone(),
            snapshot.platform(),
            snapshot.processor().clone(),
            snapshot.memory_bytes(),
            snapshot.accelerators().to_vec(),
            snapshot.interconnects().to_vec(),
            observed_at,
        )?;
        let event = match latest.as_ref() {
            None => HardwareEvent::HardwareObserved {
                observation_id: observation.observation_id().clone(),
            },
            Some((previous_snapshot, _)) if previous_snapshot == &snapshot => {
                HardwareEvent::HardwareRefreshed {
                    observation_id: observation.observation_id().clone(),
                }
            }
            Some((_, previous_observation)) => HardwareEvent::HardwareChanged {
                previous_observation_id: previous_observation.observation_id().clone(),
                observation_id: observation.observation_id().clone(),
            },
        };
        *latest = Some((snapshot, observation.clone()));
        Ok(HardwareChange::new(observation, event))
    }

    // Returns the latest validated observation when one exists.
    pub fn latest(&self) -> Result<Option<HardwareObservation>, HardwareError> {
        self.latest
            .lock()
            .map(|latest| latest.as_ref().map(|(_, observation)| observation.clone()))
            .map_err(|_| HardwareError::StateUnavailable)
    }

    // Classifies the latest boot-scoped observation without changing or refreshing its facts.
    pub fn latest_at(
        &self,
        reference_time: UnixMilliseconds,
        maximum_age_milliseconds: u64,
    ) -> Result<Option<HardwareLatestObservation>, HardwareError> {
        if maximum_age_milliseconds == 0 {
            return Err(HardwareError::InvalidObservation {
                reason: "hardware observation maximum age must be positive",
            });
        }
        let latest = self
            .latest
            .lock()
            .map_err(|_| HardwareError::StateUnavailable)?;
        let Some((_, observation)) = latest.as_ref() else {
            return Ok(None);
        };
        let age = reference_time
            .value()
            .checked_sub(observation.observed_at().value())
            .ok_or(HardwareError::InvalidObservation {
                reason: "hardware observation is later than the reference time",
            })?;
        let freshness = if age <= maximum_age_milliseconds {
            HardwareObservationFreshness::Current
        } else {
            HardwareObservationFreshness::Stale {
                age_milliseconds: age,
            }
        };
        Ok(Some(HardwareLatestObservation::new(
            observation.clone(),
            freshness,
        )))
    }
}

// Converts fixed random bytes to lowercase hexadecimal identity text.
fn hexadecimal(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}
