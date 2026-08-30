// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(unix)]

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use li_hardware_manager::{
    HardwareCommandWait, HardwareError, HardwareNativeIo, SystemHardwareNativeIo,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

// Returns an immediate deterministic timeout for native command tests.
struct TimeoutWait;

impl HardwareCommandWait for TimeoutWait {
    // Returns an immediate deterministic test timeout.
    fn timeout(&self) -> Duration {
        Duration::ZERO
    }

    // Returns a zero poll interval because this policy never polls twice.
    fn poll_interval(&self) -> Duration {
        Duration::ZERO
    }
}

// Allows a direct child to exit before bounding one inherited output pipe.
struct DescendantTimeoutWait;

impl HardwareCommandWait for DescendantTimeoutWait {
    // Returns a short deterministic ceiling for the descendant fixture.
    fn timeout(&self) -> Duration {
        Duration::from_millis(100)
    }

    // Polls frequently enough to observe the direct parent exit first.
    fn poll_interval(&self) -> Duration {
        Duration::from_millis(1)
    }
}

// Owns one unique native I/O fixture directory and removes only that directory.
struct FixtureDirectory {
    path: PathBuf,
}

impl FixtureDirectory {
    // Creates one canonical private fixture directory below the process temp root.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "li_hardware_native_{}_{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).expect("fixture directory");
        Self {
            path: fs::canonicalize(path).expect("canonical fixture directory"),
        }
    }

    // Returns one fixture-owned child path.
    fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    // Writes one private regular fixture file with an exact mode.
    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.path(name);
        let mut file = File::create(&path).expect("fixture file");
        file.write_all(bytes).expect("fixture contents");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("fixture mode");
        path
    }
}

impl Drop for FixtureDirectory {
    // Removes only the exact fixture directory owned by this test.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// Requires one invalid native input to fail without echoing its supplied path.
fn assert_redacted(result: Result<String, HardwareError>, path: &Path) {
    let error = result.expect_err("unsafe native input");
    assert!(!error.to_string().contains(&path.display().to_string()));
}

// Reads a private regular UTF-8 file and executes a private regular command.
#[test]
fn system_native_io_reads_and_runs_trusted_inputs() {
    let fixture = FixtureDirectory::new();
    let text = fixture.write("facts", b"hardware facts\n", 0o600);
    let command = fixture.write("probe", b"#!/bin/sh\nprintf 'hardware probe\\n'\n", 0o700);
    let io = SystemHardwareNativeIo::default();
    assert_eq!(io.read_text(&text).expect("file"), "hardware facts\n");
    assert_eq!(io.run(&command, &[]).expect("command"), "hardware probe\n");
}

// Rejects traversal, symlink, hard-link, directory, and unsafe-mode file inputs.
#[test]
fn system_native_io_rejects_unsafe_file_paths_and_modes() {
    let fixture = FixtureDirectory::new();
    let safe = fixture.write("safe", b"facts\n", 0o600);
    let symlink_path = fixture.path("symlink");
    symlink(&safe, &symlink_path).expect("symlink");
    let hard_link_path = fixture.path("hard-link");
    fs::hard_link(&safe, &hard_link_path).expect("hard link");
    let unsafe_mode = fixture.write("unsafe-mode", b"facts\n", 0o622);
    let empty = fixture.write("empty", b"", 0o600);
    let non_utf8 = fixture.write("non-utf8", &[0xff], 0o600);
    let directory = fixture.path("directory");
    fs::create_dir(&directory).expect("directory");
    let linked_directory = fixture.path("linked-directory");
    symlink(&fixture.path, &linked_directory).expect("directory symlink");
    let linked_parent_file = linked_directory.join("unsafe-mode");
    let io = SystemHardwareNativeIo::default();
    for path in [
        &safe,
        &hard_link_path,
        &symlink_path,
        &unsafe_mode,
        &empty,
        &non_utf8,
        &directory,
        &linked_parent_file,
    ] {
        assert_redacted(io.read_text(path), path);
    }
    assert_redacted(io.read_text(Path::new("relative")), Path::new("relative"));
    assert_redacted(
        io.read_text(&fixture.path("nested/../safe")),
        &fixture.path("nested/../safe"),
    );
}

// Rejects bounded-output overflow before retaining an unbounded native file.
#[test]
fn system_native_io_rejects_oversized_file_output() {
    let fixture = FixtureDirectory::new();
    let oversized = fixture.write("oversized", &vec![b'x'; 4 * 1024 * 1024 + 1], 0o600);
    assert!(matches!(
        SystemHardwareNativeIo::default().read_text(&oversized),
        Err(HardwareError::InvalidObservation { .. })
    ));
}

// Rejects non-executable, linked, writable, failing, empty, and unbounded commands.
#[test]
fn system_native_io_rejects_unsafe_or_failed_commands() {
    let fixture = FixtureDirectory::new();
    let non_executable = fixture.write("non-executable", b"#!/bin/sh\nprintf x\n", 0o600);
    let writable = fixture.write("writable", b"#!/bin/sh\nprintf x\n", 0o722);
    let failing = fixture.write("failing", b"#!/bin/sh\nexit 7\n", 0o700);
    let empty = fixture.write("empty-command", b"#!/bin/sh\nexit 0\n", 0o700);
    let oversized = fixture.write(
        "oversized-command",
        b"#!/bin/sh\n/usr/bin/yes x | /usr/bin/head -c 4194305\n",
        0o700,
    );
    let symlink_path = fixture.path("command-symlink");
    symlink(&failing, &symlink_path).expect("command symlink");
    let io = SystemHardwareNativeIo::default();
    for path in [
        &non_executable,
        &writable,
        &failing,
        &empty,
        &oversized,
        &symlink_path,
    ] {
        assert_redacted(io.run(path, &[]), path);
    }
}

// Rejects unbounded command arguments before spawning the configured executable.
#[test]
fn system_native_io_rejects_unbounded_command_arguments() {
    let fixture = FixtureDirectory::new();
    let command = fixture.write("probe", b"#!/bin/sh\nprintf x\n", 0o700);
    let oversized = "x".repeat(4097);
    assert!(matches!(
        SystemHardwareNativeIo::default().run(&command, &[&oversized]),
        Err(HardwareError::InvalidObservation { .. })
    ));
    let arguments = vec!["x"; 33];
    assert!(matches!(
        SystemHardwareNativeIo::default().run(&command, &arguments),
        Err(HardwareError::InvalidObservation { .. })
    ));
}

// Kills and reaps a native process when the injected wait contract times out.
#[test]
fn system_native_io_bounds_command_runtime() {
    let fixture = FixtureDirectory::new();
    let command = fixture.write("slow", b"#!/bin/sh\n/bin/sleep 60\n", 0o700);
    let io = SystemHardwareNativeIo::new(Arc::new(TimeoutWait));
    assert_eq!(
        io.run(&command, &[]).expect_err("timeout"),
        HardwareError::ProviderUnavailable
    );
}

// Kills descendants which outlive their direct parent while retaining captured stdout.
#[test]
fn system_native_io_bounds_descendant_inherited_output() {
    let fixture = FixtureDirectory::new();
    let command = fixture.write(
        "descendant",
        b"#!/bin/sh\n/bin/sleep 60 &\nprintf parent-complete\nexit 0\n",
        0o700,
    );
    let io = SystemHardwareNativeIo::new(Arc::new(DescendantTimeoutWait));
    assert_eq!(
        io.run(&command, &[]).expect_err("descendant timeout"),
        HardwareError::ProviderUnavailable
    );
}
