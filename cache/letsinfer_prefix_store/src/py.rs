// SPDX-License-Identifier: AGPL-3.0-only

// PyO3 0.22's generated wrappers trigger this Rust 1.97 Clippy lint even
// though the handwritten return types and conversions are required.
#![allow(clippy::useless_conversion)]

//! PyO3 surface consumed by the vLLM connector
//! (`letsinfer_prefix_connector`). Mirrors the Rust API one-to-one; every
//! store error surfaces as a Python exception, every miss as `None`.

use std::path::PathBuf;
use std::sync::Arc;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::format::RegionDescription;
use crate::store::{CaptureRejection, PrefixStore, RecordReader, RecordWriter, StoreConfig};

const DEFAULT_RESIDENT_CAPACITY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

fn fingerprint_from(bytes: &[u8]) -> PyResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("fingerprint must be exactly 32 bytes"))
}

#[pyclass(name = "PrefixStore", module = "letsinfer_prefix_store")]
struct PyPrefixStore {
    inner: Arc<PrefixStore>,
}

#[pymethods]
impl PyPrefixStore {
    #[new]
    #[pyo3(signature = (
        root,
        capacity_bytes,
        ttl_seconds,
        minimum_token_count,
        resident_capacity_bytes = DEFAULT_RESIDENT_CAPACITY_BYTES,
        direct_reads = true
    ))]
    fn new(
        root: PathBuf,
        capacity_bytes: u64,
        ttl_seconds: u64,
        minimum_token_count: usize,
        resident_capacity_bytes: u64,
        direct_reads: bool,
    ) -> PyResult<Self> {
        let inner = PrefixStore::open(StoreConfig {
            root,
            capacity_bytes,
            ttl_seconds,
            minimum_token_count,
            resident_capacity_bytes,
            direct_reads,
        })
        .map_err(|error| PyRuntimeError::new_err(format!("{error:#}")))?;
        Ok(Self { inner })
    }

    /// Returns a writer, or None when capture is rejected (rejection
    /// reason available via `last_rejection` semantics is deliberately
    /// omitted — the connector treats every rejection as "skip persist").
    fn begin_capture(
        &self,
        fingerprint: &[u8],
        tokens: Vec<u32>,
        regions: Vec<(String, u64)>,
    ) -> PyResult<Option<PyRecordWriter>> {
        let fingerprint = fingerprint_from(fingerprint)?;
        let regions = regions
            .into_iter()
            .map(|(name, byte_count)| RegionDescription { name, byte_count })
            .collect();
        match self.inner.begin_capture(fingerprint, &tokens, regions) {
            Ok(writer) => Ok(Some(PyRecordWriter {
                inner: Some(writer),
            })),
            Err(CaptureRejection::InvalidPlan) => {
                Err(PyValueError::new_err("invalid capture plan"))
            }
            Err(_) => Ok(None),
        }
    }

    fn longest_prefix(
        &self,
        fingerprint: &[u8],
        tokens: Vec<u32>,
        minimum_token_count: usize,
    ) -> PyResult<Option<PyRecordReader>> {
        let fingerprint = fingerprint_from(fingerprint)?;
        Ok(self
            .inner
            .longest_prefix(fingerprint, &tokens, minimum_token_count)
            .map(|reader| PyRecordReader {
                inner: Some(reader),
            }))
    }

    /// Return compatible records in prewarm priority order while
    /// greedily respecting the native byte budget.
    fn prewarm_candidates(
        &self,
        fingerprint: &[u8],
        capacity_bytes: u64,
    ) -> PyResult<Vec<(Vec<u32>, bool, u64)>> {
        let fingerprint = fingerprint_from(fingerprint)?;
        Ok(self.inner.prewarm_candidates(fingerprint, capacity_bytes))
    }

    fn touch(&self, reader: &PyRecordReader) -> PyResult<()> {
        let inner = reader
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("reader is closed"))?;
        self.inner.touch(inner);
        Ok(())
    }

    fn release_resident(&self, reader: &PyRecordReader) -> PyResult<()> {
        let inner = reader
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("reader is closed"))?;
        self.inner.release_resident(inner);
        Ok(())
    }

    fn reclaim_expired(&self, unix_time_seconds: u64) -> PyResult<()> {
        self.inner
            .reclaim_expired(unix_time_seconds)
            .map_err(|error| PyRuntimeError::new_err(format!("{error:#}")))
    }

    fn statistics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let statistics = self.inner.statistics();
        let dict = PyDict::new_bound(py);
        dict.set_item("committed_byte_count", statistics.committed_byte_count)?;
        dict.set_item("reserved_byte_count", statistics.reserved_byte_count)?;
        dict.set_item("record_count", statistics.record_count)?;
        dict.set_item("active_reader_count", statistics.active_reader_count)?;
        dict.set_item(
            "outstanding_writer_count",
            statistics.outstanding_writer_count,
        )?;
        dict.set_item("admitted_capture_count", statistics.admitted_capture_count)?;
        dict.set_item(
            "committed_capture_count",
            statistics.committed_capture_count,
        )?;
        dict.set_item("failed_capture_count", statistics.failed_capture_count)?;
        dict.set_item(
            "writer_busy_rejection_count",
            statistics.writer_busy_rejection_count,
        )?;
        dict.set_item("lookup_count", statistics.lookup_count)?;
        dict.set_item("hit_count", statistics.hit_count)?;
        dict.set_item(
            "capacity_eviction_count",
            statistics.capacity_eviction_count,
        )?;
        dict.set_item("expiry_eviction_count", statistics.expiry_eviction_count)?;
        dict.set_item(
            "integrity_eviction_count",
            statistics.integrity_eviction_count,
        )?;
        dict.set_item(
            "resident_capacity_bytes",
            statistics.resident_capacity_bytes,
        )?;
        dict.set_item("resident_used_bytes", statistics.resident_used_bytes)?;
        dict.set_item("resident_record_count", statistics.resident_record_count)?;
        dict.set_item("resident_hit_count", statistics.resident_hit_count)?;
        dict.set_item("nvme_load_count", statistics.nvme_load_count)?;
        Ok(dict)
    }
}

#[pyclass(name = "RecordWriter", module = "letsinfer_prefix_store")]
struct PyRecordWriter {
    inner: Option<RecordWriter>,
}

#[pymethods]
impl PyRecordWriter {
    /// Copy `data` into region `index`. Length must match the declared
    /// region byte count exactly.
    fn write_region(&mut self, index: usize, data: &[u8]) -> PyResult<()> {
        let writer = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("writer is closed"))?;
        let region = writer
            .writable_region(index)
            .ok_or_else(|| PyValueError::new_err(format!("region index {index} out of range")))?;
        if region.len() != data.len() {
            return Err(PyValueError::new_err(format!(
                "region {index} expects {} bytes, got {}",
                region.len(),
                data.len()
            )));
        }
        region.copy_from_slice(data);
        Ok(())
    }

    /// Copy a Python buffer directly into the aligned record allocation,
    /// avoiding a temporary `bytes` object.
    fn write_region_from(
        &mut self,
        py: Python<'_>,
        index: usize,
        data: PyBuffer<u8>,
    ) -> PyResult<()> {
        let writer = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("writer is closed"))?;
        let region = writer
            .writable_region(index)
            .ok_or_else(|| PyValueError::new_err(format!("region index {index} out of range")))?;
        data.copy_to_slice(py, region)
    }

    /// Queue the durable write; the bounded worker owns the record-sized
    /// buffer until fsync + atomic rename complete.
    #[pyo3(signature = (promote_resident = true))]
    fn commit(&mut self, promote_resident: bool) -> PyResult<()> {
        let writer = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("writer is closed"))?;
        writer
            .commit_async(promote_resident)
            .map_err(|error| PyRuntimeError::new_err(format!("{error:#}")))
    }

    /// Commit before returning. Storage backends with write-through semantics
    /// use this path so a successful engine write means the record is already
    /// durable and visible to a following lookup.
    fn commit_sync(&mut self) -> PyResult<()> {
        let writer = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("writer is closed"))?;
        writer
            .commit()
            .map_err(|error| PyRuntimeError::new_err(format!("{error:#}")))
    }

    fn cancel(&mut self) {
        if let Some(writer) = self.inner.take() {
            writer.cancel();
        }
    }
}

#[pyclass(name = "RecordReader", module = "letsinfer_prefix_store")]
struct PyRecordReader {
    inner: Option<RecordReader>,
}

#[pymethods]
impl PyRecordReader {
    #[getter]
    fn token_count(&self) -> PyResult<usize> {
        Ok(self.reader()?.token_count())
    }

    #[getter]
    fn region_names(&self) -> PyResult<Vec<String>> {
        let reader = self.reader()?;
        Ok((0..reader.region_count())
            .map(|i| {
                reader
                    .region_description(i)
                    .expect("bounded index")
                    .name
                    .clone()
            })
            .collect())
    }

    fn region_byte_count(&self, index: usize) -> PyResult<u64> {
        self.reader()?
            .region_description(index)
            .map(|region| region.byte_count)
            .ok_or_else(|| PyValueError::new_err(format!("region index {index} out of range")))
    }

    /// Read one region as bytes (CRC-verified; raises on any integrity
    /// failure — the caller must treat that as a cache miss).
    fn read_region<'py>(&self, py: Python<'py>, index: usize) -> PyResult<Bound<'py, PyBytes>> {
        let reader = self.reader()?;
        let byte_count = reader
            .region_description(index)
            .map(|region| region.byte_count)
            .ok_or_else(|| PyValueError::new_err(format!("region index {index} out of range")))?;
        let mut buffer = vec![0u8; usize::try_from(byte_count).expect("validated size")];
        reader
            .read_region(index, &mut buffer)
            .map_err(|error| PyRuntimeError::new_err(format!("{error:#}")))?;
        Ok(PyBytes::new_bound(py, &buffer))
    }

    /// Copy a validated resident region directly into a writable Python
    /// buffer, avoiding `PyBytes` and `bytearray` allocations.
    fn read_region_into(
        &self,
        py: Python<'_>,
        index: usize,
        destination: PyBuffer<u8>,
    ) -> PyResult<()> {
        let (blob, range) = self
            .reader()?
            .loaded_region(index)
            .map_err(|error| PyRuntimeError::new_err(format!("{error:#}")))?;
        destination.copy_from_slice(py, &blob.as_slice()[range])
    }

    /// Release the eviction pin without waiting for garbage collection.
    fn close(&mut self) {
        self.inner = None;
    }
}

impl PyRecordReader {
    fn reader(&self) -> PyResult<&RecordReader> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("reader is closed"))
    }
}

#[pymodule]
fn letsinfer_prefix_store(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyPrefixStore>()?;
    module.add_class::<PyRecordWriter>()?;
    module.add_class::<PyRecordReader>()?;
    Ok(())
}
