// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, File};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use li_core_interface::{NetworkInterfaceName, NodeAddress};

use crate::{
    PairingDirectLinkProvider, PairingError, PairingNativeCommand, PairingNativeCommandRunner,
};

const DIRECT_ROUTE_MAXIMUM_BYTES: usize = 8 * 1024;
const DIRECT_ROUTE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RDMA_DEVICES: usize = 64;
const MAX_SYSTEM_VALUE_BYTES: usize = 128;

// Isolates bounded sysfs reads used for direct ConnectX proof.
pub trait PairingDirectLinkIo: Send + Sync {
    // Returns whether one exact native path is a directory.
    fn is_directory(&self, path: &Path) -> Result<bool, PairingError>;

    // Reads one exact system value with an enforced byte cap.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, PairingError>;

    // Resolves one exact native link without accepting a missing target.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, PairingError>;

    // Returns sorted UTF-8 entry names from one bounded system directory.
    fn directory_names(
        &self,
        path: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<String>, PairingError>;
}

// Reads direct-link facts from the active Linux sysfs tree.
#[derive(Default)]
pub struct SystemPairingDirectLinkIo;

impl PairingDirectLinkIo for SystemPairingDirectLinkIo {
    // Checks one sysfs directory without following product-controlled input paths.
    fn is_directory(&self, path: &Path) -> Result<bool, PairingError> {
        fs::metadata(path)
            .map(|metadata| metadata.is_dir())
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Ok(false)
                } else {
                    Err(error)
                }
            })
            .map_err(|_| PairingError::DirectLinkUnavailable)
    }

    // Reads one bounded sysfs value and rejects truncation.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, PairingError> {
        if maximum_bytes == 0 {
            return Err(PairingError::DirectLinkUnavailable);
        }
        let mut file = File::open(path).map_err(|_| PairingError::DirectLinkUnavailable)?;
        let limit = u64::try_from(maximum_bytes)
            .map_err(|_| PairingError::DirectLinkUnavailable)?
            .saturating_add(1);
        let mut value = Vec::with_capacity(maximum_bytes.min(4 * 1024));
        file.by_ref()
            .take(limit)
            .read_to_end(&mut value)
            .map_err(|_| PairingError::DirectLinkUnavailable)?;
        if value.len() > maximum_bytes {
            return Err(PairingError::DirectLinkUnavailable);
        }
        Ok(value)
    }

    // Resolves one native sysfs link to its exact existing target.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, PairingError> {
        fs::canonicalize(path).map_err(|_| PairingError::DirectLinkUnavailable)
    }

    // Enumerates one bounded sysfs directory without accepting lossy names.
    fn directory_names(
        &self,
        path: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<String>, PairingError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path).map_err(|_| PairingError::DirectLinkUnavailable)? {
            let entry = entry.map_err(|_| PairingError::DirectLinkUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PairingError::DirectLinkUnavailable)?;
            names.push(name);
            if names.len() > maximum_entries {
                return Err(PairingError::DirectLinkUnavailable);
            }
        }
        names.sort();
        Ok(names)
    }
}

// Verifies live ConnectX sysfs identity and one exact gateway-free peer route.
pub struct LinuxPairingDirectLinkProvider {
    sys_class: PathBuf,
    ip_executable: PathBuf,
    io: Arc<dyn PairingDirectLinkIo>,
    runner: Arc<dyn PairingNativeCommandRunner>,
}

impl LinuxPairingDirectLinkProvider {
    // Creates one Linux proof provider from explicit sysfs and command dependencies.
    pub fn new(
        sys_class: PathBuf,
        ip_executable: PathBuf,
        io: Arc<dyn PairingDirectLinkIo>,
        runner: Arc<dyn PairingNativeCommandRunner>,
    ) -> Result<Self, PairingError> {
        if !sys_class.is_absolute() {
            return Err(PairingError::InvalidRequest {
                reason: "pairing sysfs root must be absolute",
            });
        }
        PairingNativeCommand::new(ip_executable.clone(), Vec::new())?;
        Ok(Self {
            sys_class,
            ip_executable,
            io,
            runner,
        })
    }

    // Proves one interface is live RDMA-capable mlx5 hardware with usable link capacity.
    fn verify_interface(&self, interface: &NetworkInterfaceName) -> Result<(), PairingError> {
        let root = self.sys_class.join("net").join(interface.as_str());
        if !self.io.is_directory(&root)? || !self.has_rdma_binding(interface)? {
            return Err(PairingError::DirectLinkUnavailable);
        }
        if read_unsigned(self.io.as_ref(), &root.join("carrier"))? != 1 {
            return Err(PairingError::DirectLinkUnavailable);
        }
        let state = read_text(self.io.as_ref(), &root.join("operstate"))?;
        if !matches!(state.as_str(), "up" | "unknown") {
            return Err(PairingError::DirectLinkUnavailable);
        }
        let speed = read_unsigned(self.io.as_ref(), &root.join("speed"))?;
        let mtu = read_unsigned(self.io.as_ref(), &root.join("mtu"))?;
        if speed == 0 || mtu < 1_500 {
            return Err(PairingError::DirectLinkUnavailable);
        }
        let driver = self.io.canonicalize(&root.join("device/driver"))?;
        if driver.file_name().and_then(|value| value.to_str()) != Some("mlx5_core") {
            return Err(PairingError::DirectLinkUnavailable);
        }
        Ok(())
    }

    // Requires the exact network interface to appear under at least one RDMA device.
    fn has_rdma_binding(&self, interface: &NetworkInterfaceName) -> Result<bool, PairingError> {
        let root = self.sys_class.join("infiniband");
        if !self.io.is_directory(&root)? {
            return Ok(false);
        }
        for device in self.io.directory_names(&root, MAX_RDMA_DEVICES)? {
            if !is_native_name(&device, 64) {
                return Err(PairingError::DirectLinkUnavailable);
            }
            let path = root
                .join(device)
                .join("device/net")
                .join(interface.as_str());
            if self.io.is_directory(&path)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Runs and validates one exact kernel route query for the numeric peer.
    fn verify_route(
        &self,
        interface: &NetworkInterfaceName,
        peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        let peer = canonical_peer_address(peer_address)?;
        let command = PairingNativeCommand::new(
            self.ip_executable.clone(),
            vec![
                "-oneline".to_string(),
                "route".to_string(),
                "get".to_string(),
                peer.clone(),
            ],
        )?;
        let output = self
            .runner
            .run(&command, DIRECT_ROUTE_TIMEOUT, DIRECT_ROUTE_MAXIMUM_BYTES)
            .map_err(|_| PairingError::DirectLinkUnavailable)?;
        if output.timed_out() || output.status() != 0 {
            return Err(PairingError::DirectLinkUnavailable);
        }
        let output = std::str::from_utf8(output.stdout())
            .map_err(|_| PairingError::DirectLinkUnavailable)?;
        validate_direct_route(output, interface, &peer)
    }
}

impl PairingDirectLinkProvider for LinuxPairingDirectLinkProvider {
    // Requires live ConnectX identity before proving the candidate's exact direct route.
    fn verify(
        &self,
        interface: &NetworkInterfaceName,
        peer_address: &NodeAddress,
    ) -> Result<(), PairingError> {
        self.verify_interface(interface)?;
        self.verify_route(interface, peer_address)
    }
}

// Reads one strict non-empty UTF-8 sysfs fact.
fn read_text(io: &dyn PairingDirectLinkIo, path: &Path) -> Result<String, PairingError> {
    let value = io.read(path, MAX_SYSTEM_VALUE_BYTES)?;
    let value = std::str::from_utf8(&value)
        .map_err(|_| PairingError::DirectLinkUnavailable)?
        .trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(PairingError::DirectLinkUnavailable);
    }
    Ok(value.to_string())
}

// Reads one strict non-negative sysfs integer.
fn read_unsigned(io: &dyn PairingDirectLinkIo, path: &Path) -> Result<u64, PairingError> {
    read_text(io, path)?
        .parse::<u64>()
        .map_err(|_| PairingError::DirectLinkUnavailable)
}

// Canonicalizes one numeric candidate address and rejects hostnames or unspecified peers.
fn canonical_peer_address(address: &NodeAddress) -> Result<String, PairingError> {
    let value = if let Some(value) = address.as_str().strip_prefix('[') {
        value
            .strip_suffix(']')
            .filter(|value| {
                !value
                    .chars()
                    .any(|character| matches!(character, '[' | ']'))
            })
            .ok_or(PairingError::DirectLinkUnavailable)?
    } else {
        if address
            .as_str()
            .chars()
            .any(|character| matches!(character, '[' | ']'))
        {
            return Err(PairingError::DirectLinkUnavailable);
        }
        address.as_str()
    };
    let address = IpAddr::from_str(value).map_err(|_| PairingError::DirectLinkUnavailable)?;
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return Err(PairingError::DirectLinkUnavailable);
    }
    Ok(address.to_string())
}

// Requires one unambiguous direct route through the approved interface without a gateway.
fn validate_direct_route(
    output: &str,
    interface: &NetworkInterfaceName,
    peer: &str,
) -> Result<(), PairingError> {
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() != 1 || lines[0].len() > DIRECT_ROUTE_MAXIMUM_BYTES {
        return Err(PairingError::DirectLinkUnavailable);
    }
    let fields: Vec<&str> = lines[0].split_whitespace().collect();
    if fields.first().copied() != Some(peer) || fields.iter().any(|value| *value == "via") {
        return Err(PairingError::DirectLinkUnavailable);
    }
    let devices = values_after(&fields, "dev")?;
    if devices.as_slice() != [interface.as_str()] {
        return Err(PairingError::DirectLinkUnavailable);
    }
    let sources = values_after_either(&fields, "src", "prefsrc")?;
    if sources.len() > 1 {
        return Err(PairingError::DirectLinkUnavailable);
    }
    if let Some(source) = sources.first() {
        let source = IpAddr::from_str(source).map_err(|_| PairingError::DirectLinkUnavailable)?;
        let peer = IpAddr::from_str(peer).map_err(|_| PairingError::DirectLinkUnavailable)?;
        if source.is_unspecified() || source.is_ipv4() != peer.is_ipv4() {
            return Err(PairingError::DirectLinkUnavailable);
        }
    }
    Ok(())
}

// Returns every value following one exact route keyword and rejects dangling fields.
fn values_after<'a>(fields: &'a [&str], name: &str) -> Result<Vec<&'a str>, PairingError> {
    let mut values = Vec::new();
    for (index, value) in fields.iter().enumerate() {
        if *value != name {
            continue;
        }
        values.push(
            fields
                .get(index + 1)
                .copied()
                .ok_or(PairingError::DirectLinkUnavailable)?,
        );
    }
    Ok(values)
}

// Returns route values following either equivalent source-address keyword.
fn values_after_either<'a>(
    fields: &'a [&str],
    first: &str,
    second: &str,
) -> Result<Vec<&'a str>, PairingError> {
    let mut values = values_after(fields, first)?;
    values.extend(values_after(fields, second)?);
    Ok(values)
}

// Accepts one bounded sysfs identifier without path separators or control bytes.
fn is_native_name(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}
