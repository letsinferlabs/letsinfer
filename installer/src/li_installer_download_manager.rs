// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4 * 1024 * 1024;

// Owns bounded release downloads through the verified bootstrap curl command.
pub struct DownloadManager {
    allow_insecure: bool,
    curl_command: PathBuf,
    release_base: String,
}

impl DownloadManager {
    // Creates a downloader bound to one release root and bootstrap command.
    pub fn new(curl_command: PathBuf, release_base: String, allow_insecure: bool) -> Self {
        Self {
            allow_insecure,
            curl_command,
            release_base,
        }
    }

    // Downloads one release asset without a shell or inherited output.
    pub fn download(&self, name: &str, destination: &Path) -> Result<(), String> {
        if !valid_asset_name(name) {
            return Err(format!("release asset name is invalid: {}", name));
        }
        if destination.exists() || destination.is_symlink() {
            return Err(format!(
                "release download destination already exists: {}",
                destination.display()
            ));
        }
        let url = format!("{}/{}", self.release_base.trim_end_matches('/'), name);
        validate_url(&url, self.allow_insecure)?;
        let protocols = if self.allow_insecure {
            "=https,http,file"
        } else {
            "=https"
        };
        let output = Command::new(&self.curl_command)
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                protocols,
                "--tlsv1.2",
                "--output",
            ])
            .arg(destination)
            .arg(&url)
            .output()
            .map_err(|error| format!("release download could not run: {}", error))?;
        if output.stdout.len() > MAXIMUM_DIAGNOSTIC_BYTES
            || output.stderr.len() > MAXIMUM_DIAGNOSTIC_BYTES
        {
            return Err("release download diagnostics exceeded their boundary".to_string());
        }
        if !output.status.success() {
            let diagnostics = String::from_utf8_lossy(&output.stderr);
            let detail = diagnostics
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("download failed")
                .trim();
            let _ = fs::remove_file(destination);
            return Err(format!("could not download {}: {}", name, detail));
        }
        let details = fs::symlink_metadata(destination)
            .map_err(|error| format!("cannot inspect downloaded {}: {}", name, error))?;
        if details.file_type().is_symlink() || !details.is_file() || details.len() == 0 {
            return Err(format!("downloaded release asset is invalid: {}", name));
        }
        Ok(())
    }
}

// Returns whether one release asset uses the closed filename vocabulary.
fn valid_asset_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

// Requires one release URL to use an explicitly approved transport.
fn validate_url(url: &str, allow_insecure: bool) -> Result<(), String> {
    if url.starts_with("https://")
        || (allow_insecure && (url.starts_with("http://") || url.starts_with("file://")))
    {
        Ok(())
    } else {
        Err("release URL uses an unapproved transport".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rejects path separators and shell metacharacters in release asset names.
    #[test]
    fn rejects_unsafe_asset_names() {
        assert!(!valid_asset_name("../core.tar.gz"));
        assert!(!valid_asset_name("core;run"));
        assert!(valid_asset_name("letsinfer-linux-arm64.tar.gz"));
    }
}
