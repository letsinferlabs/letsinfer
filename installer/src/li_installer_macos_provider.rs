// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::Path;
use std::process::Command;

const MAXIMUM_PROBE_BYTES: usize = 8 * 1024 * 1024;

// Collects one macOS observation through the bundled Swift and Metal provider.
pub fn observe(helper: &Path, arguments: &[String]) -> Result<String, String> {
    let details = fs::symlink_metadata(helper)
        .map_err(|error| format!("cannot inspect macOS probe: {}", error))?;
    if details.file_type().is_symlink() || !details.is_file() {
        return Err("macOS probe is unavailable".to_string());
    }
    let output = Command::new(helper)
        .args(arguments)
        .output()
        .map_err(|error| format!("macOS probe could not run: {}", error))?;
    if output.stdout.len() > MAXIMUM_PROBE_BYTES || output.stderr.len() > MAXIMUM_PROBE_BYTES {
        return Err("macOS probe output exceeded its boundary".to_string());
    }
    if !output.status.success() {
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        let detail = diagnostics
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("native provider failed")
            .trim();
        return Err(format!("macOS probe failed: {}", detail));
    }
    if !output.stderr.is_empty() {
        return Err("macOS probe wrote unexpected diagnostics".to_string());
    }
    let document = String::from_utf8(output.stdout)
        .map_err(|_| "macOS probe output is not UTF-8".to_string())?;
    if document.trim().is_empty() {
        return Err("macOS probe produced no document".to_string());
    }
    Ok(document)
}
