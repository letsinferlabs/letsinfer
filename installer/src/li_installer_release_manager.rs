// SPDX-License-Identifier: AGPL-3.0-only

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

const MAXIMUM_CHECKSUM_DOCUMENT_BYTES: u64 = 1024 * 1024;

// Stores exact SHA-256 records from the signature-verified release document.
pub struct ReleaseManager {
    records: BTreeMap<String, String>,
}

impl ReleaseManager {
    // Loads one bounded closed checksum document supplied by the bootstrap.
    pub fn load(path: &Path) -> Result<Self, String> {
        let details = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect signed checksums: {}", error))?;
        if details.file_type().is_symlink()
            || !details.is_file()
            || details.len() == 0
            || details.len() > MAXIMUM_CHECKSUM_DOCUMENT_BYTES
        {
            return Err("signed checksum document is invalid".to_string());
        }
        let mut records = BTreeMap::new();
        let reader = BufReader::new(
            File::open(path).map_err(|error| format!("cannot open signed checksums: {}", error))?,
        );
        for line in reader.lines() {
            let line = line.map_err(|error| format!("cannot read signed checksums: {}", error))?;
            let (digest, name) = line
                .split_once("  ")
                .ok_or_else(|| "signed checksum record is invalid".to_string())?;
            if !valid_digest(digest) || !valid_asset_name(name) {
                return Err("signed checksum record is invalid".to_string());
            }
            if records
                .insert(name.to_string(), digest.to_string())
                .is_some()
            {
                return Err(format!("signed checksum record is duplicated: {}", name));
            }
        }
        if records.is_empty() {
            return Err("signed checksum document is empty".to_string());
        }
        Ok(Self { records })
    }

    // Verifies one downloaded asset against its signature-bound SHA-256 identity.
    pub fn verify(&self, name: &str, path: &Path) -> Result<(), String> {
        let expected = self
            .records
            .get(name)
            .ok_or_else(|| format!("release checksum is unavailable: {}", name))?;
        let details = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect release asset {}: {}", name, error))?;
        if details.file_type().is_symlink() || !details.is_file() || details.len() == 0 {
            return Err(format!("release asset is invalid: {}", name));
        }
        let mut source = File::open(path)
            .map_err(|error| format!("cannot open release asset {}: {}", name, error))?;
        let mut digest = Sha256::new();
        let mut block = [0_u8; 1024 * 1024];
        loop {
            let count = source
                .read(&mut block)
                .map_err(|error| format!("cannot hash release asset {}: {}", name, error))?;
            if count == 0 {
                break;
            }
            digest.update(&block[..count]);
        }
        let actual = format!("{:x}", digest.finalize());
        if &actual != expected {
            return Err(format!("release asset checksum is invalid: {}", name));
        }
        Ok(())
    }
}

// Returns whether one checksum is exactly one lowercase SHA-256 identity.
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Returns whether one release asset uses the closed filename vocabulary.
fn valid_asset_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Accepts only lowercase full-length SHA-256 values.
    #[test]
    fn validates_sha256_identity() {
        assert!(valid_digest(&"a".repeat(64)));
        assert!(!valid_digest(&"A".repeat(64)));
        assert!(!valid_digest(&"a".repeat(63)));
    }
}
