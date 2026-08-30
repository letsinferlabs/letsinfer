// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::{
    run_native_benchmark_controlled, BenchmarkWorkerError, NativeBenchmarkWorkerInput,
    NativeGatewayBenchmarkTransport, SystemNativeBenchmarkClock,
    SystemNativeBenchmarkWatchdogTransport, WatchdogBenchmarkTelemetrySource,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAXIMUM_INPUT_BYTES: u64 = 2 * 1024 * 1024;

// Runs one sealed input file through native HTTPS execution and atomic owner-only evidence output.
pub fn run_native_benchmark_file(input_file: &Path) -> Result<(), BenchmarkWorkerError> {
    require_safe_absolute_file(input_file)?;
    let (input_handle, input_bytes) = read_locked_private_file(input_file, MAXIMUM_INPUT_BYTES)?;
    let input = NativeBenchmarkWorkerInput::parse(&input_bytes)?;
    publish_status(&input, "running", None, None, None)?;
    let transport = Arc::new(NativeGatewayBenchmarkTransport::new(
        input.route(),
        input.model(),
    )?);
    let watchdog_transport = Arc::new(SystemNativeBenchmarkWatchdogTransport::load(
        input.watchdog(),
        input.owner_user_id(),
    )?);
    let telemetry = Arc::new(WatchdogBenchmarkTelemetrySource::new(
        input.watchdog().clone(),
        watchdog_transport,
    )?);
    let clock = Arc::new(SystemNativeBenchmarkClock);
    let cancelled = || cancellation_requested(&input);
    let rotate = |context: String, context_index, context_count, completed_cells, total_cells| {
        await_context_rotation(
            &input,
            &context,
            context_index,
            context_count,
            completed_cells,
            total_cells,
        )
    };
    let progress = |completed_cells, total_cells| {
        publish_status(
            &input,
            "running",
            None,
            Some(json!({
                "completed_cells": completed_cells,
                "total_cells": total_cells
            })),
            None,
        )
    };
    let result = run_native_benchmark_controlled(
        &input, transport, telemetry, clock, &cancelled, &rotate, &progress,
    );
    let outcome = match result {
        Ok(output) => publish_private_file(input.output_file(), output.bytes()).and_then(|()| {
            publish_status(
                &input,
                "succeeded",
                Some(json!({
                    "raw_evidence_sha256": output.raw_evidence_sha256(),
                    "results_sha256": output.results_sha256(),
                    "completed_cells": output.completed_cells(),
                    "byte_count": output.bytes().len()
                })),
                Some(json!({
                    "completed_cells": output.completed_cells(),
                    "total_cells": output.completed_cells()
                })),
                None,
            )
        }),
        Err(error) => {
            let state = if error.is_cancelled() {
                "cancelled"
            } else {
                "failed"
            };
            publish_status(&input, state, None, None, None).and(Err(error))
        }
    };
    drop(input_handle);
    outcome
}

// Waits for one exact manager-owned placement rotation without mutating the Placement itself.
fn await_context_rotation(
    input: &NativeBenchmarkWorkerInput,
    context: &str,
    context_index: u32,
    context_count: u32,
    completed_cells: u32,
    total_cells: u32,
) -> Result<(), BenchmarkWorkerError> {
    publish_status(
        input,
        "awaiting_rotation",
        None,
        Some(json!({
            "completed_cells": completed_cells,
            "total_cells": total_cells
        })),
        Some(json!({
            "context": context,
            "context_index": context_index,
            "context_count": context_count
        })),
    )?;
    loop {
        if cancellation_requested(input) {
            return Err(BenchmarkWorkerError::cancelled());
        }
        if input.rotation_file().exists() {
            let bytes = read_private_file(input.rotation_file(), 4 * 1024)?;
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| system_output_error())?;
            if rotation_acknowledges(input, &value, context, context_index, context_count)? {
                publish_status(
                    input,
                    "running",
                    None,
                    Some(json!({
                        "completed_cells": completed_cells,
                        "total_cells": total_cells
                    })),
                    None,
                )?;
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// Validates one closed PlacementManager receipt or ignores only an exact earlier boundary.
fn rotation_acknowledges(
    input: &NativeBenchmarkWorkerInput,
    value: &Value,
    context: &str,
    context_index: u32,
    context_count: u32,
) -> Result<bool, BenchmarkWorkerError> {
    let object = value.as_object().ok_or_else(system_output_error)?;
    let expected_fields = [
        "schema_name",
        "schema_version",
        "job_id",
        "plan_sha256",
        "reset_id",
        "placement_group_id",
        "context",
        "context_index",
        "context_count",
        "expected_revision",
        "previous_revision",
        "next_revision",
        "store_generation_sha256",
        "process_generation_sha256",
        "reset_at_unix_milliseconds",
        "receipt_sha256",
    ];
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|name| !object.contains_key(*name))
        || value.get("schema_name").and_then(Value::as_str) != Some("li-benchmark-context-rotation")
        || value.get("schema_version").and_then(Value::as_u64) != Some(1)
        || value.get("job_id").and_then(Value::as_str) != Some(input.job_id())
        || value.get("plan_sha256").and_then(Value::as_str) != Some(input.plan_sha256())
        || value.get("placement_group_id").and_then(Value::as_str)
            != Some(input.placement_group_id())
        || value.get("context_count").and_then(Value::as_u64) != Some(u64::from(context_count))
    {
        return Err(system_output_error());
    }
    let acknowledged_index = value
        .get("context_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(system_output_error)?;
    if acknowledged_index < context_index {
        return Ok(false);
    }
    if acknowledged_index != context_index
        || value.get("context").and_then(Value::as_str) != Some(context)
    {
        return Err(system_output_error());
    }
    let expected_revision = positive_u64(value, "expected_revision")?;
    let previous_revision = positive_u64(value, "previous_revision")?;
    let next_revision = positive_u64(value, "next_revision")?;
    let reset_at = positive_u64(value, "reset_at_unix_milliseconds")?;
    let store_generation = digest_text(value, "store_generation_sha256")?;
    let process_generation = digest_text(value, "process_generation_sha256")?;
    let reset_id = digest_text(value, "reset_id")?;
    let receipt = digest_text(value, "receipt_sha256")?;
    let context_index_text = context_index.to_string();
    let context_count_text = context_count.to_string();
    let expected_reset_id = framed_sha256(&[
        "li-benchmark-placement-reset-v1",
        input.job_id(),
        input.plan_sha256(),
        input.placement_group_id(),
        context,
        &context_index_text,
        &context_count_text,
    ]);
    let expected_revision_text = expected_revision.to_string();
    let previous_revision_text = previous_revision.to_string();
    let next_revision_text = next_revision.to_string();
    let reset_at_text = reset_at.to_string();
    let expected_receipt = framed_sha256(&[
        "li-placement-benchmark-reset-v1",
        &reset_id,
        input.placement_group_id(),
        context,
        &context_index_text,
        &context_count_text,
        &expected_revision_text,
        &previous_revision_text,
        &next_revision_text,
        &store_generation,
        &process_generation,
        &reset_at_text,
    ]);
    if reset_id != expected_reset_id
        || receipt != expected_receipt
        || previous_revision != expected_revision
        || next_revision <= previous_revision
        || store_generation == process_generation
    {
        return Err(system_output_error());
    }
    Ok(true)
}

// Returns one positive integer from an exact receipt field.
fn positive_u64(value: &Value, name: &str) -> Result<u64, BenchmarkWorkerError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(system_output_error)
}

// Returns one lowercase SHA-256 text from an exact receipt field.
fn digest_text(value: &Value, name: &str) -> Result<String, BenchmarkWorkerError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(str::to_string)
        .ok_or_else(system_output_error)
}

// Hashes ordered receipt fields with the PlacementManager framing contract.
fn framed_sha256(fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

// Opens and exclusively locks one sealed input for the complete worker lifetime.
fn read_locked_private_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<(File, Vec<u8>), BenchmarkWorkerError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| system_input_error())?;
    require_private_metadata(&file, maximum_bytes)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(BenchmarkWorkerError::invalid(
            "native benchmark input is already active",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| system_input_error())?;
    Ok((file, bytes))
}

// Reads one owner-only regular file without following a final symbolic link.
fn read_private_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, BenchmarkWorkerError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| system_input_error())?;
    let metadata = require_private_metadata(&file, maximum_bytes)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| system_input_error())?;
    if bytes.len() as u64 != metadata.len() {
        return Err(system_input_error());
    }
    Ok(bytes)
}

// Requires one descriptor to remain a single-link owner-only bounded regular file.
fn require_private_metadata(
    file: &File,
    maximum_bytes: u64,
) -> Result<fs::Metadata, BenchmarkWorkerError> {
    let metadata = file.metadata().map_err(|_| system_input_error())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(system_input_error());
    }
    Ok(metadata)
}

// Returns whether an exact owner-only cancellation marker matches this job.
fn cancellation_requested(input: &NativeBenchmarkWorkerInput) -> bool {
    read_private_file(input.cancellation_file(), 128)
        .ok()
        .and_then(|bytes| {
            std::str::from_utf8(&bytes)
                .ok()
                .map(str::trim)
                .map(str::to_string)
        })
        .is_some_and(|value| value == input.job_id())
}

// Atomically replaces only this exact job's owner-private restart polling status.
fn publish_status(
    input: &NativeBenchmarkWorkerInput,
    state: &str,
    artifact: Option<Value>,
    progress: Option<Value>,
    rotation: Option<Value>,
) -> Result<(), BenchmarkWorkerError> {
    let path = input.status_file();
    require_safe_absolute_file(path)?;
    let parent = path.parent().ok_or_else(system_output_error)?;
    require_private_directory(parent)?;
    if path.exists() {
        let existing = read_private_file(path, 64 * 1024)?;
        let value: Value = serde_json::from_slice(&existing).map_err(|_| system_output_error())?;
        if value.get("job_id").and_then(Value::as_str) != Some(input.job_id())
            || value.get("plan_sha256").and_then(Value::as_str) != Some(input.plan_sha256())
        {
            return Err(system_output_error());
        }
    }
    let mut bytes = serde_json::to_vec(&json!({
        "schema_name": "li-benchmark-worker-status",
        "schema_version": 1,
        "job_id": input.job_id(),
        "plan_sha256": input.plan_sha256(),
        "state": state,
        "artifact": artifact,
        "progress": progress,
        "rotation": rotation
    }))
    .map_err(|_| system_output_error())?;
    bytes.push(b'\n');
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(system_output_error)?;
    let temporary = parent.join(format!(".{name}.{}.status", std::process::id()));
    write_new_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, path).map_err(|_| system_output_error())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| system_output_error())
}

// Publishes immutable evidence atomically without replacing any differing existing result.
fn publish_private_file(path: &Path, bytes: &[u8]) -> Result<(), BenchmarkWorkerError> {
    require_safe_absolute_file(path)?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 * 1024 {
        return Err(system_output_error());
    }
    let parent = path.parent().ok_or_else(system_output_error)?;
    require_private_directory(parent)?;
    match read_private_file(path, 64 * 1024 * 1024) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => return Err(system_output_error()),
        Err(_) if path.exists() => return Err(system_output_error()),
        Err(_) => {}
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(system_output_error)?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = publish_new_file(&temporary, path, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

// Writes, syncs, and atomically renames one new private evidence file.
fn publish_new_file(
    temporary: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), BenchmarkWorkerError> {
    write_new_private_file(temporary, bytes)?;
    fs::hard_link(temporary, final_path).map_err(|_| system_output_error())?;
    fs::remove_file(temporary).map_err(|_| system_output_error())?;
    let parent = final_path.parent().ok_or_else(system_output_error)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| system_output_error())
}

// Writes and syncs one exact new owner-only file without a final-link alias.
fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), BenchmarkWorkerError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| system_output_error())?;
    file.write_all(bytes).map_err(|_| system_output_error())?;
    file.sync_all().map_err(|_| system_output_error())
}

// Requires one real exact-owner 0700 directory.
fn require_private_directory(path: &Path) -> Result<(), BenchmarkWorkerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| system_output_error())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(system_output_error());
    }
    Ok(())
}

// Requires one normalization-free absolute file reference.
fn require_safe_absolute_file(path: &Path) -> Result<(), BenchmarkWorkerError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || path.file_name().is_none()
    {
        return Err(system_input_error());
    }
    Ok(())
}

// Returns one redacted private-input failure.
const fn system_input_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("native benchmark input file is unavailable or unsafe")
}

// Returns one redacted private-output failure.
const fn system_output_error() -> BenchmarkWorkerError {
    BenchmarkWorkerError::invalid("native benchmark evidence publication failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    // Creates one private real directory below a temporary test root.
    fn private_directory(root: &Path) -> PathBuf {
        let path = root.join("private");
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("permissions");
        path
    }

    // Publishes owner-only bytes idempotently and refuses differing replacement.
    #[test]
    fn private_publication_is_atomic_idempotent_and_non_replacing() {
        let root = tempfile::tempdir().expect("root");
        let directory = private_directory(root.path());
        let path = directory.join("evidence.json");
        publish_private_file(&path, b"evidence\n").expect("publish");
        publish_private_file(&path, b"evidence\n").expect("replay");
        assert!(publish_private_file(&path, b"different\n").is_err());
        let metadata = fs::symlink_metadata(&path).expect("metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(fs::read(path).expect("bytes"), b"evidence\n");
    }

    // Rejects aliased, group-readable, and oversized input files.
    #[test]
    fn private_input_rejects_unsafe_metadata_and_size() {
        let root = tempfile::tempdir().expect("root");
        let directory = private_directory(root.path());
        let path = directory.join("input.json");
        fs::write(&path, b"{}\n").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        assert_eq!(read_private_file(&path, 16).expect("read"), b"{}\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("permissions");
        assert!(read_private_file(&path, 16).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        assert!(read_private_file(&path, 2).is_err());
        let link = directory.join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("link");
        assert!(read_private_file(&link, 16).is_err());
    }

    // Builds one exact PlacementManager receipt for a selected worker context boundary.
    fn rotation_receipt(
        input: &NativeBenchmarkWorkerInput,
        context: &str,
        context_index: u32,
        context_count: u32,
    ) -> Value {
        let context_index_text = context_index.to_string();
        let context_count_text = context_count.to_string();
        let reset_id = framed_sha256(&[
            "li-benchmark-placement-reset-v1",
            input.job_id(),
            input.plan_sha256(),
            input.placement_group_id(),
            context,
            &context_index_text,
            &context_count_text,
        ]);
        let expected_revision = 7_u64;
        let previous_revision = 7_u64;
        let next_revision = 11_u64;
        let store_generation = "3".repeat(64);
        let process_generation = "4".repeat(64);
        let reset_at = 900_u64;
        let receipt = framed_sha256(&[
            "li-placement-benchmark-reset-v1",
            &reset_id,
            input.placement_group_id(),
            context,
            &context_index_text,
            &context_count_text,
            &expected_revision.to_string(),
            &previous_revision.to_string(),
            &next_revision.to_string(),
            &store_generation,
            &process_generation,
            &reset_at.to_string(),
        ]);
        json!({
            "schema_name": "li-benchmark-context-rotation",
            "schema_version": 1,
            "job_id": input.job_id(),
            "plan_sha256": input.plan_sha256(),
            "reset_id": reset_id,
            "placement_group_id": input.placement_group_id(),
            "context": context,
            "context_index": context_index,
            "context_count": context_count,
            "expected_revision": expected_revision,
            "previous_revision": previous_revision,
            "next_revision": next_revision,
            "store_generation_sha256": store_generation,
            "process_generation_sha256": process_generation,
            "reset_at_unix_milliseconds": reset_at,
            "receipt_sha256": receipt
        })
    }

    // Accepts only a complete native receipt and ignores exactly one earlier ordered boundary.
    #[test]
    fn context_rotation_requires_exact_process_store_and_revision_receipt() {
        let input = NativeBenchmarkWorkerInput::rotation_fixture();
        let receipt = rotation_receipt(&input, "32k", 2, 3);
        assert_eq!(
            rotation_acknowledges(&input, &receipt, "32k", 2, 3).expect("receipt"),
            true
        );
        let stale = rotation_receipt(&input, "short", 1, 3);
        assert_eq!(
            rotation_acknowledges(&input, &stale, "32k", 2, 3).expect("stale receipt"),
            false
        );

        for name in [
            "job_id",
            "plan_sha256",
            "placement_group_id",
            "context",
            "context_index",
            "context_count",
            "expected_revision",
            "previous_revision",
            "next_revision",
            "store_generation_sha256",
            "process_generation_sha256",
            "reset_at_unix_milliseconds",
            "reset_id",
            "receipt_sha256",
        ] {
            let mut drifted = receipt.clone();
            drifted[name] = match name {
                "job_id" | "placement_group_id" => json!("9".repeat(32)),
                "context" => json!("64k"),
                "context_index" => json!(3),
                "context_count" => json!(4),
                "expected_revision" | "previous_revision" => json!(8),
                "next_revision" => json!(12),
                "reset_at_unix_milliseconds" => json!(901),
                _ => json!("9".repeat(64)),
            };
            assert!(
                rotation_acknowledges(&input, &drifted, "32k", 2, 3).is_err(),
                "{name} drift was admitted"
            );
        }
        let mut added = receipt;
        added["foreign"] = json!(true);
        assert!(rotation_acknowledges(&input, &added, "32k", 2, 3).is_err());
    }
}
