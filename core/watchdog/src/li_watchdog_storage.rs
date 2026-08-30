// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;

use crate::li_watchdog_native_io::{prepare_watchdog_directory, storage_io_error};
use crate::{
    WatchdogError, WatchdogEventJournal, WatchdogRing, WatchdogRingHistory, WatchdogRingLayout,
    WatchdogRollup, WatchdogSafetyEvent, WatchdogSample, WatchdogStorageProvider,
};

const WATCHDOG_RAW_INTERVAL_MILLISECONDS: u64 = 1_000;
const WATCHDOG_MINUTE_INTERVAL_MILLISECONDS: u64 = 60_000;
const WATCHDOG_QUARTER_INTERVAL_MILLISECONDS: u64 = 900_000;
const WATCHDOG_RAW_CAPACITY: u64 = 86_400;
const WATCHDOG_MINUTE_CAPACITY: u64 = 43_200;
const WATCHDOG_QUARTER_CAPACITY: u64 = 35_040;

// Defines the three fixed native ring capacities without changing their intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogStorageLayout {
    raw: WatchdogRingLayout,
    minute: WatchdogRingLayout,
    quarter: WatchdogRingLayout,
}

impl WatchdogStorageLayout {
    // Creates the exact production Watchdog retention layout.
    pub fn production() -> Self {
        Self::new(
            WATCHDOG_RAW_CAPACITY,
            WATCHDOG_MINUTE_CAPACITY,
            WATCHDOG_QUARTER_CAPACITY,
        )
        .expect("fixed Watchdog production storage layout")
    }

    // Creates one capacity-scaled layout with the immutable native intervals.
    pub fn new(
        raw_capacity: u64,
        minute_capacity: u64,
        quarter_capacity: u64,
    ) -> Result<Self, WatchdogError> {
        Ok(Self {
            raw: WatchdogRingLayout::new(WATCHDOG_RAW_INTERVAL_MILLISECONDS, raw_capacity)?,
            minute: WatchdogRingLayout::new(
                WATCHDOG_MINUTE_INTERVAL_MILLISECONDS,
                minute_capacity,
            )?,
            quarter: WatchdogRingLayout::new(
                WATCHDOG_QUARTER_INTERVAL_MILLISECONDS,
                quarter_capacity,
            )?,
        })
    }
}

impl Default for WatchdogStorageLayout {
    // Returns the exact production retention layout.
    fn default() -> Self {
        Self::production()
    }
}

// Selects one of the three established Watchdog history resolutions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogResolution {
    Raw,
    Minute,
    QuarterHour,
}

// Persists native Watchdog samples, rollups, and safety events in bounded native rings.
pub struct FilesystemWatchdogStorage {
    state: Mutex<FilesystemWatchdogStorageState>,
}

impl FilesystemWatchdogStorage {
    // Opens the exact production sample and safety-event rings beneath one private root.
    pub fn open(root: &Path) -> Result<Self, WatchdogError> {
        Self::open_with_layout(root, WatchdogStorageLayout::production())
    }

    // Opens one capacity-scaled but format-identical layout for composition and tests.
    pub fn open_with_layout(
        root: &Path,
        layout: WatchdogStorageLayout,
    ) -> Result<Self, WatchdogError> {
        if root.as_os_str().is_empty() || root.as_os_str().as_bytes().len() > 4_095 {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog storage root is empty or too long",
            });
        }
        let directory = prepare_watchdog_directory(root)?;
        let raw = WatchdogRing::open(&root.join("raw.ring"), layout.raw)?;
        let minute = WatchdogRing::open(&root.join("minute.ring"), layout.minute)?;
        let quarter = WatchdogRing::open(&root.join("quarter-hour.ring"), layout.quarter)?;
        let events =
            WatchdogEventJournal::open(&root.join("events.ring"), layout.raw.capacity().max(2))?;
        directory
            .sync_all()
            .map_err(|_| storage_io_error("storage directory entries could not be synchronized"))?;
        let latest = raw.latest()?;
        let accepted_next_sequence = next_after(latest.as_ref())?;
        let minute_rollup =
            rebuild_rollup(&raw, WATCHDOG_MINUTE_INTERVAL_MILLISECONDS, latest.as_ref())?;
        let quarter_rollup = rebuild_rollup(
            &raw,
            WATCHDOG_QUARTER_INTERVAL_MILLISECONDS,
            latest.as_ref(),
        )?;
        Ok(Self {
            state: Mutex::new(FilesystemWatchdogStorageState {
                _directory: directory,
                raw,
                minute,
                quarter,
                events,
                minute_rollup,
                quarter_rollup,
                latest_sample: latest,
                accepted_next_sequence,
                raw_dirty: false,
                minute_dirty: false,
                quarter_dirty: false,
                events_dirty: false,
            }),
        })
    }

    // Queries one exact retained ring and returns explicit missing buckets.
    pub fn history(
        &self,
        resolution: WatchdogResolution,
        start_milliseconds: u64,
        end_milliseconds: u64,
        maximum_samples: usize,
    ) -> Result<WatchdogRingHistory, WatchdogError> {
        let state = self.lock_state()?;
        state
            .ring(resolution)
            .query(start_milliseconds, end_milliseconds, maximum_samples)
    }

    // Returns the latest complete raw sample without exposing storage mutation state.
    pub fn latest_sample(&self) -> Result<Option<WatchdogSample>, WatchdogError> {
        Ok(self.lock_state()?.latest_sample.clone())
    }

    // Returns one immutable native ring layout for bounded protocol composition.
    pub fn history_layout(
        &self,
        resolution: WatchdogResolution,
    ) -> Result<WatchdogRingLayout, WatchdogError> {
        Ok(self.lock_state()?.ring(resolution).layout())
    }

    // Acquires the single storage lifecycle lock or returns a stable poisoned-state failure.
    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, FilesystemWatchdogStorageState>, WatchdogError> {
        self.state
            .lock()
            .map_err(|_| WatchdogError::StateUnavailable)
    }
}

impl WatchdogStorageProvider for FilesystemWatchdogStorage {
    // Returns the next sequence after the greatest retained CRC-valid raw sample.
    fn next_sequence(&self) -> Result<u64, WatchdogError> {
        Ok(self.lock_state()?.accepted_next_sequence)
    }

    // Records one sample exactly once, completing rollup slots before its raw commit marker.
    fn record_sample(&self, sample: &WatchdogSample) -> Result<(), WatchdogError> {
        let mut state = self.lock_state()?;
        if sample.sequence() < state.accepted_next_sequence {
            return match state.raw.find_sequence(sample.sequence())? {
                Some(existing) if existing == *sample => Ok(()),
                _ => Err(WatchdogError::InvalidContract {
                    reason: "Watchdog sample replay conflicts with retained storage",
                }),
            };
        }
        if sample.sequence() != state.accepted_next_sequence {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog sample sequence is not the next storage head",
            });
        }

        let mut minute_rollup = state.minute_rollup.clone();
        let mut quarter_rollup = state.quarter_rollup.clone();
        let minute = minute_rollup.push(sample);
        let quarter = quarter_rollup.push(sample);
        if let Some(completed) = &minute {
            state.minute.write(completed)?;
        }
        if let Some(completed) = &quarter {
            state.quarter.write(completed)?;
        }
        state.raw.write(sample)?;

        state.minute_rollup = minute_rollup;
        state.quarter_rollup = quarter_rollup;
        state.minute_dirty |= minute.is_some();
        state.quarter_dirty |= quarter.is_some();
        state.raw_dirty = true;
        state.latest_sample = Some(sample.clone());
        state.accepted_next_sequence =
            sample
                .sequence()
                .checked_add(1)
                .ok_or(WatchdogError::InvalidContract {
                    reason: "Watchdog storage sequence overflowed",
                })?;
        Ok(())
    }

    // Records one deterministic safety event exactly once across replay and restart.
    fn record_event(&self, event: &WatchdogSafetyEvent) -> Result<(), WatchdogError> {
        let mut state = self.lock_state()?;
        let retained = state
            .latest_sample
            .as_ref()
            .is_some_and(|sample| sample.sequence() == event.sequence())
            || state.raw.find_sequence(event.sequence())?.is_some();
        if !retained {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog event does not reference a retained sample",
            });
        }
        let recorded = state.events.record(event)?;
        state.events_dirty |= recorded;
        Ok(())
    }

    // Synchronizes dirty sample, rollup, and safety-event state without advancing on failure.
    fn flush(&self) -> Result<(), WatchdogError> {
        let mut state = self.lock_state()?;
        if state.raw_dirty {
            state.raw.synchronize()?;
        }
        if state.minute_dirty {
            state.minute.synchronize()?;
        }
        if state.quarter_dirty {
            state.quarter.synchronize()?;
        }
        if state.events_dirty {
            state.events.synchronize()?;
        }
        state.raw_dirty = false;
        state.minute_dirty = false;
        state.quarter_dirty = false;
        state.events_dirty = false;
        Ok(())
    }
}

// Holds the one-writer native storage and rollup lifecycle behind the provider lock.
struct FilesystemWatchdogStorageState {
    _directory: File,
    raw: WatchdogRing,
    minute: WatchdogRing,
    quarter: WatchdogRing,
    events: WatchdogEventJournal,
    minute_rollup: WatchdogRollup,
    quarter_rollup: WatchdogRollup,
    latest_sample: Option<WatchdogSample>,
    accepted_next_sequence: u64,
    raw_dirty: bool,
    minute_dirty: bool,
    quarter_dirty: bool,
    events_dirty: bool,
}

impl FilesystemWatchdogStorageState {
    // Selects one immutable ring without exposing storage mutation ownership.
    fn ring(&self, resolution: WatchdogResolution) -> &WatchdogRing {
        match resolution {
            WatchdogResolution::Raw => &self.raw,
            WatchdogResolution::Minute => &self.minute,
            WatchdogResolution::QuarterHour => &self.quarter,
        }
    }
}

// Computes the next positive sequence after one recovered raw ring head.
fn next_after(latest: Option<&WatchdogSample>) -> Result<u64, WatchdogError> {
    match latest {
        Some(sample) => sample
            .sequence()
            .checked_add(1)
            .filter(|sequence| *sequence != 0)
            .ok_or(WatchdogError::InvalidContract {
                reason: "Watchdog retained sequence cannot advance",
            }),
        None => Ok(1),
    }
}

// Rebuilds the active rollup bucket from every raw sample still retained after restart.
fn rebuild_rollup(
    raw: &WatchdogRing,
    interval_milliseconds: u64,
    latest: Option<&WatchdogSample>,
) -> Result<WatchdogRollup, WatchdogError> {
    let mut rollup = WatchdogRollup::new(interval_milliseconds)?;
    let Some(latest) = latest else {
        return Ok(rollup);
    };
    let raw_layout = raw.layout();
    let latest_bucket = latest.unix_milliseconds() / raw_layout.interval_milliseconds();
    let rollup_start_milliseconds =
        (latest.unix_milliseconds() / interval_milliseconds) * interval_milliseconds;
    let rollup_first_bucket = rollup_start_milliseconds / raw_layout.interval_milliseconds();
    let retained_first_bucket = latest_bucket.saturating_sub(raw_layout.capacity() - 1);
    let first_bucket = rollup_first_bucket.max(retained_first_bucket);
    let start_milliseconds = first_bucket * raw_layout.interval_milliseconds();
    let maximum_samples =
        usize::try_from(raw_layout.capacity()).map_err(|_| WatchdogError::InvalidContract {
            reason: "Watchdog ring capacity exceeds this platform",
        })?;
    let history = raw.query(
        start_milliseconds,
        latest.unix_milliseconds(),
        maximum_samples,
    )?;
    for sample in history.samples() {
        let completed = rollup.push(sample);
        if completed.is_some() {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog retained raw bucket is internally inconsistent",
            });
        }
    }
    Ok(rollup)
}
