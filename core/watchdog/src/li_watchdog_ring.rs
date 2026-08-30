// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use crate::li_watchdog_native_io::{open_watchdog_file, storage_io_error, validate_storage_file};
use crate::{
    decode_watchdog_record, encode_watchdog_record, WatchdogError, WatchdogSample,
    WATCHDOG_RECORD_BYTES,
};

const WATCHDOG_RING_SCAN_RECORDS: u64 = 32;

// Defines one fixed-interval, fixed-capacity Watchdog ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogRingLayout {
    interval_milliseconds: u64,
    capacity: u64,
}

impl WatchdogRingLayout {
    // Creates one bounded ring layout whose byte size fits native file offsets.
    pub fn new(interval_milliseconds: u64, capacity: u64) -> Result<Self, WatchdogError> {
        if interval_milliseconds == 0
            || capacity == 0
            || capacity
                .checked_mul(WATCHDOG_RECORD_BYTES as u64)
                .is_none_or(|bytes| bytes > i64::MAX as u64)
        {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog ring layout is invalid or too large",
            });
        }
        Ok(Self {
            interval_milliseconds,
            capacity,
        })
    }

    // Returns the exact time bucket width used to select ring slots.
    pub const fn interval_milliseconds(self) -> u64 {
        self.interval_milliseconds
    }

    // Returns the exact number of fixed record slots in the ring.
    pub const fn capacity(self) -> u64 {
        self.capacity
    }

    // Returns the closed byte extent occupied by this ring.
    fn byte_length(self) -> u64 {
        self.capacity * WATCHDOG_RECORD_BYTES as u64
    }
}

// Isolates fixed-offset ring I/O so failures remain deterministic in tests.
pub trait WatchdogRingFile: Send + Sync {
    // Returns the current regular-file length.
    fn length(&self) -> Result<u64, WatchdogError>;

    // Extends one newly created or interrupted ring to its closed byte extent.
    fn set_length(&self, length: u64) -> Result<(), WatchdogError>;

    // Reads at most one bounded byte range from an exact offset.
    fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, WatchdogError>;

    // Writes at most one bounded byte range to an exact offset.
    fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, WatchdogError>;

    // Makes all completed writes durable at an explicit flush boundary.
    fn synchronize(&self) -> Result<(), WatchdogError>;
}

// Carries samples and explicit missing buckets from one bounded history query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogRingHistory {
    samples: Vec<WatchdogSample>,
    missing_buckets: Vec<u64>,
}

impl WatchdogRingHistory {
    // Returns the ordered valid samples found in the requested range.
    pub fn samples(&self) -> &[WatchdogSample] {
        &self.samples
    }

    // Returns every overwritten, torn, corrupt, or never-written requested bucket.
    pub fn missing_buckets(&self) -> &[u64] {
        &self.missing_buckets
    }
}

// Owns one exact slot-compatible Watchdog ring.
pub struct WatchdogRing {
    layout: WatchdogRingLayout,
    file: Arc<dyn WatchdogRingFile>,
}

impl WatchdogRing {
    // Opens one secure filesystem ring without changing its C-compatible layout.
    pub fn open(path: &Path, layout: WatchdogRingLayout) -> Result<Self, WatchdogError> {
        Self::with_file(layout, open_watchdog_fixed_file(path)?)
    }

    // Creates one ring over an injected fixed-offset file capability.
    pub fn with_file(
        layout: WatchdogRingLayout,
        file: Arc<dyn WatchdogRingFile>,
    ) -> Result<Self, WatchdogError> {
        let expected = layout.byte_length();
        let observed = file.length()?;
        if observed > expected {
            return Err(storage_io_error("ring file exceeds its closed capacity"));
        }
        if observed < expected {
            file.set_length(expected)?;
        }
        if file.length()? != expected {
            return Err(storage_io_error("ring file has an incomplete extent"));
        }
        Ok(Self { layout, file })
    }

    // Returns the immutable interval and capacity of this ring.
    pub const fn layout(&self) -> WatchdogRingLayout {
        self.layout
    }

    // Writes one CRC-protected sample to its exact wrapping time bucket.
    pub fn write(&self, sample: &WatchdogSample) -> Result<(), WatchdogError> {
        let record = encode_watchdog_record(sample)?;
        let bucket = sample.unix_milliseconds() / self.layout.interval_milliseconds;
        self.write_exact(self.bucket_offset(bucket)?, &record)
    }

    // Reads one exact bucket and represents missing or corrupt bytes as a gap.
    pub fn read_bucket(&self, bucket: u64) -> Result<Option<WatchdogSample>, WatchdogError> {
        let mut record = [0_u8; WATCHDOG_RECORD_BYTES];
        self.read_exact(self.bucket_offset(bucket)?, &mut record)?;
        let sample = match decode_watchdog_record(&record) {
            Ok(sample)
                if sample.unix_milliseconds() / self.layout.interval_milliseconds == bucket =>
            {
                sample
            }
            _ => return Ok(None),
        };
        Ok(Some(sample))
    }

    // Queries a bounded inclusive time range and reports every unavailable bucket.
    pub fn query(
        &self,
        start_milliseconds: u64,
        end_milliseconds: u64,
        maximum_samples: usize,
    ) -> Result<WatchdogRingHistory, WatchdogError> {
        if end_milliseconds < start_milliseconds
            || maximum_samples == 0
            || maximum_samples as u64 > self.layout.capacity
        {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog ring query range or limit is invalid",
            });
        }
        let first = start_milliseconds / self.layout.interval_milliseconds;
        let final_bucket = end_milliseconds / self.layout.interval_milliseconds;
        let bucket_count = final_bucket
            .checked_sub(first)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(WatchdogError::InvalidContract {
                reason: "Watchdog ring query range or limit is invalid",
            })?;
        if bucket_count > self.layout.capacity {
            return Err(WatchdogError::InvalidContract {
                reason: "Watchdog ring query exceeds retained history",
            });
        }
        let mut samples = Vec::new();
        let mut missing_buckets = Vec::new();
        let mut bucket = first;
        loop {
            match self.read_bucket(bucket)? {
                Some(sample)
                    if sample.unix_milliseconds() >= start_milliseconds
                        && sample.unix_milliseconds() <= end_milliseconds =>
                {
                    samples.push(sample);
                    if samples.len() == maximum_samples {
                        break;
                    }
                }
                _ => missing_buckets.push(bucket),
            }
            if bucket == final_bucket || bucket == u64::MAX {
                break;
            }
            bucket += 1;
        }
        Ok(WatchdogRingHistory {
            samples,
            missing_buckets,
        })
    }

    // Returns the greatest valid sequence anywhere in the wrapping ring.
    pub fn latest(&self) -> Result<Option<WatchdogSample>, WatchdogError> {
        let mut latest: Option<WatchdogSample> = None;
        self.scan_valid_records(|candidate| {
            if latest
                .as_ref()
                .is_none_or(|current| candidate.sequence() > current.sequence())
            {
                latest = Some(candidate);
            }
            true
        })?;
        Ok(latest)
    }

    // Finds one exact retained sequence without treating unrelated corrupt slots as fatal.
    pub fn find_sequence(&self, sequence: u64) -> Result<Option<WatchdogSample>, WatchdogError> {
        let mut found = None;
        self.scan_valid_records(|candidate| {
            if candidate.sequence() == sequence {
                found = Some(candidate);
                return false;
            }
            true
        })?;
        Ok(found)
    }

    // Visits CRC-valid records in their exact wrapping slots using bounded block reads.
    fn scan_valid_records(
        &self,
        mut visitor: impl FnMut(WatchdogSample) -> bool,
    ) -> Result<(), WatchdogError> {
        let mut records = [0_u8; WATCHDOG_RING_SCAN_RECORDS as usize * WATCHDOG_RECORD_BYTES];
        for first_slot in (0..self.layout.capacity).step_by(WATCHDOG_RING_SCAN_RECORDS as usize) {
            let record_count =
                (self.layout.capacity - first_slot).min(WATCHDOG_RING_SCAN_RECORDS) as usize;
            let byte_count = record_count * WATCHDOG_RECORD_BYTES;
            self.read_exact(
                first_slot * WATCHDOG_RECORD_BYTES as u64,
                &mut records[..byte_count],
            )?;
            for (index, record) in records[..byte_count]
                .chunks_exact(WATCHDOG_RECORD_BYTES)
                .enumerate()
            {
                let Ok(candidate) = decode_watchdog_record(record) else {
                    continue;
                };
                let slot = first_slot + index as u64;
                let bucket = candidate.unix_milliseconds() / self.layout.interval_milliseconds;
                if bucket % self.layout.capacity == slot && !visitor(candidate) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    // Synchronizes every completed slot write at one explicit crash boundary.
    pub fn synchronize(&self) -> Result<(), WatchdogError> {
        self.file.synchronize()
    }

    // Maps one time bucket to the exact wrapping record offset.
    fn bucket_offset(&self, bucket: u64) -> Result<u64, WatchdogError> {
        (bucket % self.layout.capacity)
            .checked_mul(WATCHDOG_RECORD_BYTES as u64)
            .ok_or(WatchdogError::InvalidContract {
                reason: "Watchdog ring offset overflowed",
            })
    }

    // Reads one complete fixed-size record and zero-fills an interrupted extent.
    fn read_exact(&self, offset: u64, output: &mut [u8]) -> Result<(), WatchdogError> {
        let mut consumed = 0;
        while consumed < output.len() {
            let count = self
                .file
                .read_at(offset + consumed as u64, &mut output[consumed..])?;
            if count == 0 {
                output[consumed..].fill(0);
                return Ok(());
            }
            consumed += count;
        }
        Ok(())
    }

    // Writes one complete fixed-size record despite bounded partial native writes.
    fn write_exact(&self, offset: u64, input: &[u8]) -> Result<(), WatchdogError> {
        let mut consumed = 0;
        while consumed < input.len() {
            let count = self
                .file
                .write_at(offset + consumed as u64, &input[consumed..])?;
            if count == 0 {
                return Err(storage_io_error("ring write made no progress"));
            }
            consumed += count;
        }
        Ok(())
    }
}

// Opens one owner-bound fixed-offset Watchdog file behind the shared injected I/O contract.
pub(crate) fn open_watchdog_fixed_file(
    path: &Path,
) -> Result<Arc<dyn WatchdogRingFile>, WatchdogError> {
    let (file, _) = open_watchdog_file(path)?;
    validate_storage_file(&file)?;
    Ok(Arc::new(SystemWatchdogRingFile { file }))
}

// Wraps one verified native file behind the injected ring-I/O contract.
struct SystemWatchdogRingFile {
    file: File,
}

impl WatchdogRingFile for SystemWatchdogRingFile {
    // Returns the verified ring file's current extent.
    fn length(&self) -> Result<u64, WatchdogError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|_| storage_io_error("ring length could not be read"))
    }

    // Extends one bounded ring file without rewriting retained legacy slots.
    fn set_length(&self, length: u64) -> Result<(), WatchdogError> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: the verified file descriptor remains open and length fits off_t.
            let result =
                unsafe { libc::posix_fallocate(self.file.as_raw_fd(), 0, length as libc::off_t) };
            if result != 0 {
                return Err(storage_io_error("ring extent could not be allocated"));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.file
                .set_len(length)
                .map_err(|_| storage_io_error("ring extent could not be allocated"))
        }
    }

    // Reads one native fixed-offset range and preserves interrupted-call retry semantics.
    fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, WatchdogError> {
        loop {
            match self.file.read_at(output, offset) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(storage_io_error("ring record could not be read")),
            }
        }
    }

    // Writes one native fixed-offset range and preserves interrupted-call retry semantics.
    fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, WatchdogError> {
        loop {
            match self.file.write_at(input, offset) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(storage_io_error("ring record could not be written")),
            }
        }
    }

    // Flushes ring data without changing metadata or the on-disk record identity.
    fn synchronize(&self) -> Result<(), WatchdogError> {
        self.file
            .sync_data()
            .map_err(|_| storage_io_error("ring could not be synchronized"))
    }
}
