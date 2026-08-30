// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use crate::li_watchdog_native_io::storage_io_error;
use crate::li_watchdog_ring::open_watchdog_fixed_file;
use crate::{
    watchdog_crc32, WatchdogError, WatchdogRingFile, WatchdogSafetyAction, WatchdogSafetyEvent,
};

const WATCHDOG_EVENT_MAGIC: [u8; 4] = *b"LIWE";
const WATCHDOG_EVENT_VERSION: u8 = 1;
const WATCHDOG_EVENT_RECORD_BYTES: usize = 64;
const WATCHDOG_EVENT_CRC_OFFSET: usize = 60;
const WATCHDOG_EVENT_GENERATION_BYTES: usize = 32;
const WATCHDOG_EVENT_SCAN_RECORDS: u64 = 64;
const WATCHDOG_EVENT_PREPARING_MARKER: u8 = 0x5a;
const WATCHDOG_EVENT_COMMITTED_MARKER: u8 = 0xa5;

// Identifies one closed safety-event kind in the native journal.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum WatchdogEventKind {
    Warning = 1,
    EngineExit = 2,
    ProtectionTrip = 3,
}

// Identifies one closed safety-event reason in the native journal.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum WatchdogEventReason {
    HostMemoryWarning = 1,
    ProtectedProcessExited = 2,
    CgroupOomKill = 3,
}

// Carries one exact event identity independently of its append ordinal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WatchdogEventIdentity {
    kind: WatchdogEventKind,
    reason: WatchdogEventReason,
    severity: u8,
    generation: [u8; WATCHDOG_EVENT_GENERATION_BYTES],
    sequence: u64,
    action: Option<WatchdogSafetyAction>,
    containment_complete: Option<bool>,
}

impl WatchdogEventIdentity {
    // Validates and closes one manager-owned safety event for durable storage.
    fn from_event(event: &WatchdogSafetyEvent) -> Result<Self, WatchdogError> {
        let kind = match event.kind() {
            "protection.warning" => WatchdogEventKind::Warning,
            "engine.exit" => WatchdogEventKind::EngineExit,
            "protection.trip" => WatchdogEventKind::ProtectionTrip,
            _ => return Err(event_contract_error()),
        };
        let reason = match event.reason() {
            "host_memory_warning" => WatchdogEventReason::HostMemoryWarning,
            "protected_process_exited" => WatchdogEventReason::ProtectedProcessExited,
            "cgroup_oom_kill" => WatchdogEventReason::CgroupOomKill,
            _ => return Err(event_contract_error()),
        };
        let generation: [u8; WATCHDOG_EVENT_GENERATION_BYTES] = event
            .generation()
            .as_bytes()
            .try_into()
            .map_err(|_| event_contract_error())?;
        if event.sequence() == 0
            || !generation
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(event_contract_error());
        }
        let identity = Self {
            kind,
            reason,
            severity: event.severity(),
            generation,
            sequence: event.sequence(),
            action: event.action(),
            containment_complete: event.containment_complete(),
        };
        identity.validate()?;
        Ok(identity)
    }

    // Reconstructs one CRC-validated event identity from closed record fields.
    fn from_record(record: &[u8; WATCHDOG_EVENT_RECORD_BYTES]) -> Result<Self, WatchdogError> {
        let kind = match record[5] {
            1 => WatchdogEventKind::Warning,
            2 => WatchdogEventKind::EngineExit,
            3 => WatchdogEventKind::ProtectionTrip,
            _ => return Err(event_corruption_error()),
        };
        let reason = match record[6] {
            1 => WatchdogEventReason::HostMemoryWarning,
            2 => WatchdogEventReason::ProtectedProcessExited,
            3 => WatchdogEventReason::CgroupOomKill,
            _ => return Err(event_corruption_error()),
        };
        let action = match record[8] {
            0 => None,
            1 => Some(WatchdogSafetyAction::Stop),
            2 => Some(WatchdogSafetyAction::Kill),
            _ => return Err(event_corruption_error()),
        };
        let containment_complete = match record[9] {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(event_corruption_error()),
        };
        let identity = Self {
            kind,
            reason,
            severity: record[7],
            generation: record[28..60]
                .try_into()
                .expect("fixed event generation field"),
            sequence: u64::from_le_bytes(record[20..28].try_into().expect("fixed sequence field")),
            action,
            containment_complete,
        };
        identity.validate().map_err(|_| event_corruption_error())?;
        Ok(identity)
    }

    // Enforces the exact kind, reason, severity, and containment combinations emitted by Watchdog.
    fn validate(&self) -> Result<(), WatchdogError> {
        let closed = matches!(
            (
                self.kind,
                self.reason,
                self.severity,
                self.action,
                self.containment_complete,
            ),
            (
                WatchdogEventKind::Warning,
                WatchdogEventReason::HostMemoryWarning,
                1,
                None,
                None,
            ) | (
                WatchdogEventKind::EngineExit,
                WatchdogEventReason::ProtectedProcessExited,
                2,
                Some(WatchdogSafetyAction::Stop),
                Some(_),
            ) | (
                WatchdogEventKind::ProtectionTrip,
                WatchdogEventReason::CgroupOomKill,
                3,
                Some(WatchdogSafetyAction::Kill),
                Some(_),
            )
        );
        if !closed
            || self.sequence == 0
            || !self
                .generation
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(event_contract_error());
        }
        Ok(())
    }
}

// Carries one complete decoded journal record with its append ordering.
struct WatchdogEventRecord {
    ordinal: u64,
    identity: WatchdogEventIdentity,
}

// Describes one empty, interrupted, or committed physical journal slot.
enum WatchdogEventSlot {
    Empty,
    Preparing(WatchdogEventRecord),
    Committed(WatchdogEventRecord),
}

// Owns one bounded fixed-record safety-event journal without another database writer.
pub(crate) struct WatchdogEventJournal {
    logical_capacity: u64,
    physical_capacity: u64,
    file: Arc<dyn WatchdogRingFile>,
    next_ordinal: u64,
    records: BTreeMap<u64, WatchdogEventIdentity>,
    identities: BTreeSet<WatchdogEventIdentity>,
    publication_uncertain: bool,
}

impl WatchdogEventJournal {
    // Opens one owner-bound native journal and reconstructs its exact retained event set.
    pub(crate) fn open(path: &Path, capacity: u64) -> Result<Self, WatchdogError> {
        Self::with_file(capacity, open_watchdog_fixed_file(path)?)
    }

    // Reconstructs one journal over an injected fixed-offset file capability.
    fn with_file(
        logical_capacity: u64,
        file: Arc<dyn WatchdogRingFile>,
    ) -> Result<Self, WatchdogError> {
        let physical_capacity = event_physical_capacity(logical_capacity)?;
        let expected = event_file_bytes(logical_capacity)?;
        let observed = file.length()?;
        if observed > expected {
            return Err(storage_io_error(
                "safety event journal exceeds its closed capacity",
            ));
        }
        if observed < expected {
            file.set_length(expected)?;
        }
        if file.length()? != expected {
            return Err(storage_io_error(
                "safety event journal has an incomplete extent",
            ));
        }
        let (decoded_records, preparing_slot) = scan_records(physical_capacity, file.as_ref())?;
        let next_ordinal = validate_record_set(
            logical_capacity,
            physical_capacity,
            &decoded_records,
            preparing_slot,
        )?;
        let records = decoded_records
            .into_iter()
            .map(|record| (record.ordinal, record.identity))
            .collect::<BTreeMap<_, _>>();
        let identities = retained_identities(&records, logical_capacity);
        Ok(Self {
            logical_capacity,
            physical_capacity,
            file,
            next_ordinal,
            records,
            identities,
            publication_uncertain: false,
        })
    }

    // Appends one exact event or returns replay without consuming another journal ordinal.
    pub(crate) fn record(&mut self, event: &WatchdogSafetyEvent) -> Result<bool, WatchdogError> {
        if self.publication_uncertain {
            self.reconstruct()?;
            self.publication_uncertain = false;
        }
        let identity = WatchdogEventIdentity::from_event(event)?;
        if self.identities.contains(&identity) {
            return Ok(false);
        }
        let ordinal = self.next_ordinal;
        let successor = ordinal
            .checked_add(1)
            .ok_or(WatchdogError::InvalidContract {
                reason: "Watchdog safety event journal ordinal overflowed",
            })?;
        let slot = (ordinal - 1) % self.physical_capacity;
        let overwritten_ordinal = self
            .records
            .keys()
            .copied()
            .find(|previous| (previous - 1) % self.physical_capacity == slot);
        let previous = match self.read_slot(slot)? {
            WatchdogEventSlot::Empty => None,
            WatchdogEventSlot::Preparing(previous) if previous.ordinal == ordinal => None,
            WatchdogEventSlot::Preparing(_) => return Err(event_corruption_error()),
            WatchdogEventSlot::Committed(previous) if previous.ordinal == ordinal => {
                self.file.synchronize()?;
                self.reconstruct()?;
                if self.next_ordinal != successor || !self.identities.contains(&previous.identity) {
                    return Err(event_corruption_error());
                }
                return if previous.identity == identity {
                    Ok(false)
                } else {
                    self.record(event)
                };
            }
            WatchdogEventSlot::Committed(previous)
                if previous
                    .ordinal
                    .checked_add(self.physical_capacity)
                    .is_some_and(|next| next == ordinal) =>
            {
                Some(previous)
            }
            WatchdogEventSlot::Committed(_) => return Err(event_corruption_error()),
        };
        let offset = slot * WATCHDOG_EVENT_RECORD_BYTES as u64;
        write_exact(
            self.file.as_ref(),
            offset,
            &[0_u8; WATCHDOG_EVENT_RECORD_BYTES],
        )?;
        self.file.synchronize()?;
        let preparing = encode_record(ordinal, &identity, WATCHDOG_EVENT_PREPARING_MARKER);
        write_exact(self.file.as_ref(), offset, &preparing)?;
        self.file.synchronize()?;
        let committed = encode_record(ordinal, &identity, WATCHDOG_EVENT_COMMITTED_MARKER);
        self.publication_uncertain = true;
        write_exact(self.file.as_ref(), offset, &committed)?;
        self.file.synchronize()?;
        if let Some(overwritten_ordinal) = overwritten_ordinal {
            self.records.remove(&overwritten_ordinal);
        }
        if let Some(previous) = previous {
            self.records.remove(&previous.ordinal);
        }
        self.records.insert(ordinal, identity);
        self.identities = retained_identities(&self.records, self.logical_capacity);
        self.next_ordinal = successor;
        self.publication_uncertain = false;
        Ok(true)
    }

    // Synchronizes every complete event record at one explicit Watchdog flush boundary.
    pub(crate) fn synchronize(&self) -> Result<(), WatchdogError> {
        self.file.synchronize()
    }

    // Reads and classifies one exact wrapping journal slot.
    fn read_slot(&self, slot: u64) -> Result<WatchdogEventSlot, WatchdogError> {
        let mut record = [0_u8; WATCHDOG_EVENT_RECORD_BYTES];
        read_exact(
            self.file.as_ref(),
            slot * WATCHDOG_EVENT_RECORD_BYTES as u64,
            &mut record,
        )?;
        decode_slot(&record)
    }

    // Reconstructs committed publication state after an uncertain final synchronization.
    fn reconstruct(&mut self) -> Result<(), WatchdogError> {
        let (decoded_records, preparing_slot) =
            scan_records(self.physical_capacity, self.file.as_ref())?;
        let next_ordinal = validate_record_set(
            self.logical_capacity,
            self.physical_capacity,
            &decoded_records,
            preparing_slot,
        )?;
        let records = decoded_records
            .into_iter()
            .map(|record| (record.ordinal, record.identity))
            .collect::<BTreeMap<_, _>>();
        self.identities = retained_identities(&records, self.logical_capacity);
        self.records = records;
        self.next_ordinal = next_ordinal;
        Ok(())
    }

    // Reports whether one exact event remains inside the logical replay window.
    #[cfg(test)]
    fn retains(&self, event: &WatchdogSafetyEvent) -> bool {
        WatchdogEventIdentity::from_event(event)
            .is_ok_and(|identity| self.identities.contains(&identity))
    }
}

// Returns one spare physical slot after validating the closed logical capacity.
fn event_physical_capacity(logical_capacity: u64) -> Result<u64, WatchdogError> {
    logical_capacity
        .checked_add(1)
        .filter(|_| logical_capacity >= 2)
        .ok_or(WatchdogError::InvalidContract {
            reason: "Watchdog safety event journal capacity is invalid",
        })
}

// Returns the exact fixed journal extent after validating capacity and native offsets.
fn event_file_bytes(logical_capacity: u64) -> Result<u64, WatchdogError> {
    let physical_capacity = event_physical_capacity(logical_capacity)?;
    physical_capacity
        .checked_mul(WATCHDOG_EVENT_RECORD_BYTES as u64)
        .filter(|bytes| *bytes <= i64::MAX as u64)
        .ok_or(WatchdogError::InvalidContract {
            reason: "Watchdog safety event journal capacity is invalid",
        })
}

// Scans every fixed slot and rejects nonzero corrupt records rather than losing safety history.
fn scan_records(
    capacity: u64,
    file: &dyn WatchdogRingFile,
) -> Result<(Vec<WatchdogEventRecord>, Option<(u64, u64)>), WatchdogError> {
    let mut records = Vec::new();
    let mut preparing_slot = None;
    let mut bytes = [0_u8; WATCHDOG_EVENT_SCAN_RECORDS as usize * WATCHDOG_EVENT_RECORD_BYTES];
    for first_slot in (0..capacity).step_by(WATCHDOG_EVENT_SCAN_RECORDS as usize) {
        let record_count = (capacity - first_slot).min(WATCHDOG_EVENT_SCAN_RECORDS) as usize;
        let byte_count = record_count * WATCHDOG_EVENT_RECORD_BYTES;
        read_exact(
            file,
            first_slot * WATCHDOG_EVENT_RECORD_BYTES as u64,
            &mut bytes[..byte_count],
        )?;
        for (index, input) in bytes[..byte_count]
            .chunks_exact(WATCHDOG_EVENT_RECORD_BYTES)
            .enumerate()
        {
            let record: &[u8; WATCHDOG_EVENT_RECORD_BYTES] =
                input.try_into().expect("fixed event record chunk");
            let slot = first_slot + index as u64;
            match decode_slot(record)? {
                WatchdogEventSlot::Empty => {}
                WatchdogEventSlot::Preparing(record) => {
                    if (record.ordinal - 1) % capacity != slot
                        || preparing_slot.replace((slot, record.ordinal)).is_some()
                    {
                        return Err(event_corruption_error());
                    }
                }
                WatchdogEventSlot::Committed(record) => {
                    if (record.ordinal - 1) % capacity != slot {
                        return Err(event_corruption_error());
                    }
                    records.push(record);
                }
            }
        }
    }
    Ok((records, preparing_slot))
}

// Requires one contiguous retained ordinal window and at most one interrupted next slot.
fn validate_record_set(
    logical_capacity: u64,
    physical_capacity: u64,
    records: &[WatchdogEventRecord],
    preparing_slot: Option<(u64, u64)>,
) -> Result<u64, WatchdogError> {
    let maximum = records
        .iter()
        .map(|record| record.ordinal)
        .max()
        .unwrap_or(0);
    let next_ordinal = maximum
        .checked_add(1)
        .filter(|ordinal| *ordinal != 0)
        .ok_or_else(event_corruption_error)?;
    if preparing_slot.is_some_and(|(slot, ordinal)| {
        slot != (next_ordinal - 1) % physical_capacity || ordinal != next_ordinal
    }) {
        return Err(event_corruption_error());
    }
    if maximum == 0 {
        return if records.is_empty() {
            Ok(next_ordinal)
        } else {
            Err(event_corruption_error())
        };
    }
    let committed_count = records.len() as u64;
    let complete_count = maximum.min(physical_capacity);
    let interrupted_count = maximum.min(logical_capacity);
    if committed_count != interrupted_count
        && (preparing_slot.is_some() || committed_count != complete_count)
    {
        return Err(event_corruption_error());
    }
    let first = maximum - committed_count + 1;
    let ordinals = records
        .iter()
        .map(|record| record.ordinal)
        .collect::<BTreeSet<_>>();
    if ordinals.len() != records.len()
        || ordinals.first() != Some(&first)
        || ordinals.last() != Some(&maximum)
    {
        return Err(event_corruption_error());
    }
    let retained_first = maximum - maximum.min(logical_capacity) + 1;
    let identities = records
        .iter()
        .filter(|record| record.ordinal >= retained_first)
        .map(|record| &record.identity)
        .collect::<BTreeSet<_>>();
    if identities.len()
        != records
            .iter()
            .filter(|record| record.ordinal >= retained_first)
            .count()
    {
        return Err(event_corruption_error());
    }
    Ok(next_ordinal)
}

// Selects only the newest logical identity window from the spare-slot physical record set.
fn retained_identities(
    records: &BTreeMap<u64, WatchdogEventIdentity>,
    logical_capacity: u64,
) -> BTreeSet<WatchdogEventIdentity> {
    records
        .iter()
        .rev()
        .take(logical_capacity as usize)
        .map(|(_, identity)| identity.clone())
        .collect()
}

// Encodes one append ordinal and exact safety identity into the closed CRC-protected record.
fn encode_record(
    ordinal: u64,
    identity: &WatchdogEventIdentity,
    publication_marker: u8,
) -> [u8; WATCHDOG_EVENT_RECORD_BYTES] {
    let mut record = [0_u8; WATCHDOG_EVENT_RECORD_BYTES];
    record[..4].copy_from_slice(&WATCHDOG_EVENT_MAGIC);
    record[4] = WATCHDOG_EVENT_VERSION;
    record[5] = identity.kind as u8;
    record[6] = identity.reason as u8;
    record[7] = identity.severity;
    record[8] = match identity.action {
        None => 0,
        Some(WatchdogSafetyAction::Stop) => 1,
        Some(WatchdogSafetyAction::Kill) => 2,
    };
    record[9] = match identity.containment_complete {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    record[10] = publication_marker;
    record[12..20].copy_from_slice(&ordinal.to_le_bytes());
    record[20..28].copy_from_slice(&identity.sequence.to_le_bytes());
    record[28..60].copy_from_slice(&identity.generation);
    let checksum = watchdog_crc32(&record[..WATCHDOG_EVENT_CRC_OFFSET]);
    record[WATCHDOG_EVENT_CRC_OFFSET..].copy_from_slice(&checksum.to_le_bytes());
    record
}

// Classifies one empty slot or decodes one CRC-valid preparing or committed exact record.
fn decode_slot(
    record: &[u8; WATCHDOG_EVENT_RECORD_BYTES],
) -> Result<WatchdogEventSlot, WatchdogError> {
    if record.iter().all(|byte| *byte == 0) {
        return Ok(WatchdogEventSlot::Empty);
    }
    if !matches!(
        record[10],
        WATCHDOG_EVENT_PREPARING_MARKER | WATCHDOG_EVENT_COMMITTED_MARKER
    ) {
        return Err(event_corruption_error());
    }
    let checksum = u32::from_le_bytes(
        record[WATCHDOG_EVENT_CRC_OFFSET..]
            .try_into()
            .expect("fixed event CRC field"),
    );
    if record[..4] != WATCHDOG_EVENT_MAGIC
        || record[4] != WATCHDOG_EVENT_VERSION
        || record[11] != 0
        || checksum != watchdog_crc32(&record[..WATCHDOG_EVENT_CRC_OFFSET])
    {
        return Err(event_corruption_error());
    }
    let ordinal = u64::from_le_bytes(record[12..20].try_into().expect("fixed ordinal field"));
    if ordinal == 0 {
        return Err(event_corruption_error());
    }
    let decoded = WatchdogEventRecord {
        ordinal,
        identity: WatchdogEventIdentity::from_record(record)?,
    };
    if record[10] == WATCHDOG_EVENT_PREPARING_MARKER {
        Ok(WatchdogEventSlot::Preparing(decoded))
    } else {
        Ok(WatchdogEventSlot::Committed(decoded))
    }
}

// Reads one complete range while preserving bounded partial-read behavior.
fn read_exact(
    file: &dyn WatchdogRingFile,
    offset: u64,
    output: &mut [u8],
) -> Result<(), WatchdogError> {
    let mut consumed = 0;
    while consumed < output.len() {
        let count = file.read_at(offset + consumed as u64, &mut output[consumed..])?;
        if count == 0 {
            output[consumed..].fill(0);
            return Ok(());
        }
        consumed += count;
    }
    Ok(())
}

// Writes one complete range or fails without changing journal memory state.
fn write_exact(
    file: &dyn WatchdogRingFile,
    offset: u64,
    input: &[u8],
) -> Result<(), WatchdogError> {
    let mut consumed = 0;
    while consumed < input.len() {
        let count = file.write_at(offset + consumed as u64, &input[consumed..])?;
        if count == 0 {
            return Err(storage_io_error(
                "safety event journal write made no progress",
            ));
        }
        consumed += count;
    }
    Ok(())
}

// Creates one stable closed-contract failure for a manager event outside native vocabulary.
const fn event_contract_error() -> WatchdogError {
    WatchdogError::InvalidContract {
        reason: "Watchdog safety event is outside the native journal contract",
    }
}

// Creates one stable fail-closed corruption result for retained safety-event bytes.
const fn event_corruption_error() -> WatchdogError {
    WatchdogError::InvalidContract {
        reason: "Watchdog safety event journal is corrupt",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        encode_record, WatchdogEventIdentity, WatchdogEventJournal,
        WATCHDOG_EVENT_COMMITTED_MARKER, WATCHDOG_EVENT_PREPARING_MARKER,
        WATCHDOG_EVENT_RECORD_BYTES,
    };
    use crate::{WatchdogError, WatchdogRingFile, WatchdogSafetyEvent};

    // Holds deterministic fixed-offset bytes and fault controls for journal tests.
    #[derive(Default)]
    struct EventFileState {
        bytes: Vec<u8>,
        write_budget: Option<usize>,
        zero_write: bool,
        synchronization_attempts: usize,
        fail_synchronization_at: Option<usize>,
        synchronization_count: usize,
    }

    // Supplies bounded partial I/O and exact failures without native filesystem timing.
    struct EventFileMock {
        maximum_chunk: usize,
        state: Mutex<EventFileState>,
    }

    impl EventFileMock {
        // Creates one empty injected event file with bounded individual operations.
        fn new(maximum_chunk: usize) -> Self {
            Self {
                maximum_chunk,
                state: Mutex::new(EventFileState::default()),
            }
        }

        // Selects the total remaining bytes permitted across future writes.
        fn set_write_budget(&self, budget: Option<usize>) {
            self.state.lock().unwrap().write_budget = budget;
        }

        // Selects whether the next write boundary reports no progress.
        fn set_zero_write(&self, enabled: bool) {
            self.state.lock().unwrap().zero_write = enabled;
        }

        // Selects one exact future synchronization attempt for deterministic failure.
        fn fail_at_next_synchronization(&self, offset: usize) {
            let mut state = self.state.lock().unwrap();
            state.fail_synchronization_at = Some(state.synchronization_attempts + offset);
        }

        // Flips one retained byte without repairing its CRC.
        fn corrupt(&self, offset: usize) {
            self.state.lock().unwrap().bytes[offset] ^= 1;
        }

        // Replaces one exact byte for deterministic marker-corruption coverage.
        fn replace_byte(&self, offset: usize, value: u8) {
            self.state.lock().unwrap().bytes[offset] = value;
        }

        // Replaces one complete physical record for deterministic ordinal-boundary coverage.
        fn replace_record(&self, slot: usize, record: &[u8; WATCHDOG_EVENT_RECORD_BYTES]) {
            let offset = slot * WATCHDOG_EVENT_RECORD_BYTES;
            self.state.lock().unwrap().bytes[offset..offset + record.len()].copy_from_slice(record);
        }

        // Returns a stable copy for proving failure does not rewrite retained state.
        fn bytes(&self) -> Vec<u8> {
            self.state.lock().unwrap().bytes.clone()
        }

        // Returns the number of successful explicit synchronization boundaries.
        fn synchronization_count(&self) -> usize {
            self.state.lock().unwrap().synchronization_count
        }
    }

    impl WatchdogRingFile for EventFileMock {
        // Returns the current injected file extent.
        fn length(&self) -> Result<u64, WatchdogError> {
            Ok(self.state.lock().unwrap().bytes.len() as u64)
        }

        // Resizes the injected file exactly to the requested bounded extent.
        fn set_length(&self, length: u64) -> Result<(), WatchdogError> {
            let length = usize::try_from(length)
                .map_err(|_| WatchdogError::provider("test", "length exceeds platform"))?;
            self.state.lock().unwrap().bytes.resize(length, 0);
            Ok(())
        }

        // Reads at most one configured chunk from an exact offset.
        fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, WatchdogError> {
            let offset = usize::try_from(offset)
                .map_err(|_| WatchdogError::provider("test", "offset exceeds platform"))?;
            let state = self.state.lock().unwrap();
            if offset >= state.bytes.len() {
                return Ok(0);
            }
            let count = output
                .len()
                .min(self.maximum_chunk)
                .min(state.bytes.len() - offset);
            output[..count].copy_from_slice(&state.bytes[offset..offset + count]);
            Ok(count)
        }

        // Writes one configured chunk or returns the exact injected failure boundary.
        fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, WatchdogError> {
            let offset = usize::try_from(offset)
                .map_err(|_| WatchdogError::provider("test", "offset exceeds platform"))?;
            let mut state = self.state.lock().unwrap();
            if state.zero_write {
                return Ok(0);
            }
            let budget = state.write_budget.unwrap_or(usize::MAX);
            if budget == 0 {
                return Err(WatchdogError::provider("test", "injected torn write"));
            }
            let count = input
                .len()
                .min(self.maximum_chunk)
                .min(state.bytes.len().saturating_sub(offset))
                .min(budget);
            if count == 0 {
                return Err(WatchdogError::provider("test", "write exceeds extent"));
            }
            state.bytes[offset..offset + count].copy_from_slice(&input[..count]);
            if let Some(remaining) = &mut state.write_budget {
                *remaining -= count;
            }
            Ok(count)
        }

        // Records one synchronization attempt and fails only its exact injected boundary.
        fn synchronize(&self) -> Result<(), WatchdogError> {
            let mut state = self.state.lock().unwrap();
            state.synchronization_attempts += 1;
            if state.fail_synchronization_at == Some(state.synchronization_attempts) {
                state.fail_synchronization_at = None;
                return Err(WatchdogError::provider("test", "injected sync failure"));
            }
            state.synchronization_count += 1;
            Ok(())
        }
    }

    // Creates one deterministic warning identity within the closed manager vocabulary.
    fn warning(sequence: u64, generation: char) -> WatchdogSafetyEvent {
        WatchdogSafetyEvent::new(
            "protection.warning",
            "host_memory_warning",
            1,
            &generation.to_string().repeat(32),
            sequence,
            None,
            None,
        )
    }

    // Proves create, replay, restart, full wrap, and eviction preserve exact bounded identity.
    #[test]
    fn journal_reconstructs_replay_and_wraps_at_its_closed_capacity() {
        let file = Arc::new(EventFileMock::new(7));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        assert_eq!(file.bytes().len(), 3 * WATCHDOG_EVENT_RECORD_BYTES);
        assert!(journal.record(&warning(1, 'a')).unwrap());
        assert!(journal.record(&warning(2, 'b')).unwrap());
        assert!(!journal.record(&warning(2, 'b')).unwrap());
        journal.synchronize().unwrap();
        drop(journal);

        let mut restarted = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        assert!(!restarted.record(&warning(1, 'a')).unwrap());
        assert!(restarted.record(&warning(3, 'c')).unwrap());
        assert!(!restarted.record(&warning(3, 'c')).unwrap());
        drop(restarted);

        let mut wrapped = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        assert!(wrapped.record(&warning(1, 'a')).unwrap());
        assert!(!wrapped.record(&warning(3, 'c')).unwrap());
        assert!(file.synchronization_count() >= 1);
    }

    // Proves restart recognizes one torn preparing slot and retries the same event exactly once.
    #[test]
    fn journal_restart_recovers_a_torn_candidate_before_commit() {
        let file = Arc::new(EventFileMock::new(11));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        file.set_write_budget(Some(20));
        assert!(journal.record(&warning(1, 'a')).is_err());
        drop(journal);

        file.set_write_budget(None);
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        assert!(journal.record(&warning(1, 'a')).unwrap());
        assert!(!journal.record(&warning(1, 'a')).unwrap());
        drop(journal);

        let mut restarted = WatchdogEventJournal::with_file(2, file).unwrap();
        assert!(!restarted.record(&warning(1, 'a')).unwrap());
    }

    // Proves no-progress and synchronization failures remain retryable without false replay.
    #[test]
    fn journal_failures_do_not_advance_memory_or_suppress_retry() {
        let file = Arc::new(EventFileMock::new(11));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        file.set_zero_write(true);
        assert!(journal.record(&warning(1, 'a')).is_err());
        file.set_zero_write(false);
        assert!(journal.record(&warning(1, 'a')).unwrap());

        file.fail_at_next_synchronization(1);
        assert!(journal.record(&warning(2, 'b')).is_err());
        assert!(journal.record(&warning(2, 'b')).unwrap());
        let synchronized = file.synchronization_count();
        journal.synchronize().unwrap();
        assert_eq!(file.synchronization_count(), synchronized + 1);
    }

    // Proves a corrupt retained record fails restart without changing any native bytes.
    #[test]
    fn journal_restart_rejects_corruption_without_rewriting() {
        let file = Arc::new(EventFileMock::new(WATCHDOG_EVENT_RECORD_BYTES));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        journal.record(&warning(1, 'a')).unwrap();
        drop(journal);
        file.corrupt(28);
        let retained = file.bytes();

        assert!(WatchdogEventJournal::with_file(2, file.clone()).is_err());
        assert_eq!(file.bytes(), retained);
        assert!(WatchdogEventJournal::with_file(0, file.clone()).is_err());
        assert!(WatchdogEventJournal::with_file(1, file).is_err());
    }

    // Proves every publication sync failure reconstructs correctly when empty, non-full, or wrapped.
    #[test]
    fn journal_recovers_each_publication_sync_boundary_in_every_capacity_state() {
        for state in 0..3 {
            for synchronization_boundary in 1..=3 {
                let file = Arc::new(EventFileMock::new(9));
                let logical_capacity = if state == 1 { 3 } else { 2 };
                let mut journal =
                    WatchdogEventJournal::with_file(logical_capacity, file.clone()).unwrap();
                let (retained_before, candidate) = match state {
                    0 => (Vec::new(), warning(1, 'a')),
                    1 => {
                        let first = warning(1, 'a');
                        assert!(journal.record(&first).unwrap());
                        (vec![first], warning(2, 'b'))
                    }
                    2 => {
                        let first = warning(1, 'a');
                        let second = warning(2, 'b');
                        let third = warning(3, 'c');
                        assert!(journal.record(&first).unwrap());
                        assert!(journal.record(&second).unwrap());
                        assert!(journal.record(&third).unwrap());
                        assert!(!journal.retains(&first));
                        (vec![second, third], warning(4, 'd'))
                    }
                    _ => unreachable!("closed journal test state"),
                };
                file.fail_at_next_synchronization(synchronization_boundary);
                assert!(journal.record(&candidate).is_err());
                drop(journal);

                let mut restarted =
                    WatchdogEventJournal::with_file(logical_capacity, file).unwrap();
                if synchronization_boundary < 3 {
                    for retained in &retained_before {
                        assert!(restarted.retains(retained));
                    }
                    assert!(!restarted.retains(&candidate));
                    assert!(restarted.record(&candidate).unwrap());
                } else {
                    assert!(restarted.retains(&candidate));
                    assert!(!restarted.record(&candidate).unwrap());
                    if state == 2 {
                        assert!(!restarted.retains(&retained_before[0]));
                        assert!(restarted.retains(&retained_before[1]));
                    } else {
                        for retained in &retained_before {
                            assert!(restarted.retains(retained));
                        }
                    }
                }
            }
        }
    }

    // Proves an uncertain final publication is reconciled before replay lookup or another append.
    #[test]
    fn journal_reconciles_a_failed_final_marker_sync_before_same_process_retry() {
        let file = Arc::new(EventFileMock::new(13));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        let candidate = warning(1, 'a');
        file.fail_at_next_synchronization(3);

        assert!(journal.record(&candidate).is_err());
        assert!(!journal.retains(&candidate));
        assert!(!journal.record(&candidate).unwrap());
        assert!(journal.retains(&candidate));
        drop(journal);

        let mut restarted = WatchdogEventJournal::with_file(2, file).unwrap();
        assert!(!restarted.record(&candidate).unwrap());

        let file = Arc::new(EventFileMock::new(13));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        let first = warning(1, 'a');
        let stale_after_commit = warning(2, 'b');
        let retained = warning(3, 'c');
        let committed = warning(4, 'd');
        assert!(journal.record(&first).unwrap());
        assert!(journal.record(&stale_after_commit).unwrap());
        assert!(journal.record(&retained).unwrap());
        file.fail_at_next_synchronization(3);
        assert!(journal.record(&committed).is_err());
        assert!(journal.retains(&stale_after_commit));
        assert!(journal.record(&stale_after_commit).unwrap());
        assert!(journal.retains(&committed));
        assert!(journal.retains(&stale_after_commit));
        assert!(!journal.retains(&retained));
    }

    // Proves marker corruption of a retained committed event cannot masquerade as an append.
    #[test]
    fn journal_rejects_a_preparing_marker_on_the_newest_committed_record() {
        let file = Arc::new(EventFileMock::new(WATCHDOG_EVENT_RECORD_BYTES));
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        journal.record(&warning(1, 'a')).unwrap();
        journal.record(&warning(2, 'b')).unwrap();
        journal.record(&warning(3, 'c')).unwrap();
        drop(journal);
        file.replace_byte(
            2 * WATCHDOG_EVENT_RECORD_BYTES + 10,
            WATCHDOG_EVENT_PREPARING_MARKER,
        );
        let retained = file.bytes();

        assert!(WatchdogEventJournal::with_file(2, file.clone()).is_err());
        assert_eq!(file.bytes(), retained);
    }

    // Proves ordinal overflow is rejected before any native journal byte is mutated.
    #[test]
    fn journal_preflights_ordinal_increment_before_publication() {
        let file = Arc::new(EventFileMock::new(WATCHDOG_EVENT_RECORD_BYTES));
        drop(WatchdogEventJournal::with_file(2, file.clone()).unwrap());
        for (index, ordinal) in ((u64::MAX - 3)..=(u64::MAX - 1)).enumerate() {
            let event = warning(index as u64 + 1, char::from(b'a' + index as u8));
            let identity = WatchdogEventIdentity::from_event(&event).unwrap();
            let record = encode_record(ordinal, &identity, WATCHDOG_EVENT_COMMITTED_MARKER);
            let slot = ((ordinal - 1) % 3) as usize;
            file.replace_record(slot, &record);
        }
        let mut journal = WatchdogEventJournal::with_file(2, file.clone()).unwrap();
        let retained = file.bytes();

        assert!(journal.record(&warning(4, 'd')).is_err());
        assert_eq!(file.bytes(), retained);
        assert!(file
            .bytes()
            .chunks_exact(WATCHDOG_EVENT_RECORD_BYTES)
            .all(|record| record[10] == WATCHDOG_EVENT_COMMITTED_MARKER));
    }
}
