// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use li_core_interface::{NetworkInterfaceName, NodeAddress};
use li_pairing_manager::{
    LinuxPairingDirectLinkProvider, PairingDirectLinkIo, PairingDirectLinkProvider, PairingError,
    PairingNativeCommand, PairingNativeCommandOutput, PairingNativeCommandRunner,
    PairingNativeProcess,
};

// Supplies deterministic sysfs paths to the production direct-link provider.
#[derive(Default)]
struct MockIo {
    directories: Mutex<BTreeSet<PathBuf>>,
    values: Mutex<BTreeMap<PathBuf, Vec<u8>>>,
    canonical: Mutex<BTreeMap<PathBuf, PathBuf>>,
    entries: Mutex<BTreeMap<PathBuf, Vec<String>>>,
}

impl MockIo {
    // Changes whether one exact fixture path exists as a directory.
    fn set_directory(&self, path: &str, is_directory: bool) {
        let path = PathBuf::from(path);
        let mut values = self.directories.lock().expect("directories");
        if is_directory {
            values.insert(path);
        } else {
            values.remove(&path);
        }
    }

    // Changes one exact bounded fixture value.
    fn set_value(&self, path: &str, value: &[u8]) {
        self.values
            .lock()
            .expect("values")
            .insert(PathBuf::from(path), value.to_vec());
    }

    // Changes one exact symlink resolution fixture.
    fn set_canonical(&self, path: &str, value: &str) {
        self.canonical
            .lock()
            .expect("canonical")
            .insert(PathBuf::from(path), PathBuf::from(value));
    }

    // Changes one exact bounded directory listing fixture.
    fn set_entries(&self, path: &str, values: &[&str]) {
        self.entries.lock().expect("entries").insert(
            PathBuf::from(path),
            values.iter().map(|value| (*value).to_string()).collect(),
        );
    }
}

impl PairingDirectLinkIo for MockIo {
    // Returns the exact fixture directory state.
    fn is_directory(&self, path: &Path) -> Result<bool, PairingError> {
        Ok(self.directories.lock().expect("directories").contains(path))
    }

    // Returns one exact fixture value while enforcing the production byte bound.
    fn read(&self, path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, PairingError> {
        let value = self
            .values
            .lock()
            .expect("values")
            .get(path)
            .cloned()
            .ok_or(PairingError::DirectLinkUnavailable)?;
        if value.len() > maximum_bytes {
            return Err(PairingError::DirectLinkUnavailable);
        }
        Ok(value)
    }

    // Returns one exact fixture symlink target.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, PairingError> {
        self.canonical
            .lock()
            .expect("canonical")
            .get(path)
            .cloned()
            .ok_or(PairingError::DirectLinkUnavailable)
    }

    // Returns one sorted fixture listing while enforcing its entry bound.
    fn directory_names(
        &self,
        path: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<String>, PairingError> {
        let mut values = self
            .entries
            .lock()
            .expect("entries")
            .get(path)
            .cloned()
            .ok_or(PairingError::DirectLinkUnavailable)?;
        if values.len() > maximum_entries {
            return Err(PairingError::DirectLinkUnavailable);
        }
        values.sort();
        Ok(values)
    }
}

// Captures one exact bounded route command invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RunCall {
    command: PairingNativeCommand,
    timeout: Duration,
    maximum_output_bytes: usize,
}

// Supplies deterministic route-command results.
#[derive(Default)]
struct MockRunner {
    calls: Mutex<Vec<RunCall>>,
    outputs: Mutex<VecDeque<Result<PairingNativeCommandOutput, PairingError>>>,
}

impl MockRunner {
    // Queues one exact route-command result.
    fn push(&self, output: Result<PairingNativeCommandOutput, PairingError>) {
        self.outputs.lock().expect("outputs").push_back(output);
    }
}

impl PairingNativeCommandRunner for MockRunner {
    // Records exact route argv, timeout, and output bound before returning the fixture.
    fn run(
        &self,
        command: &PairingNativeCommand,
        timeout: Duration,
        maximum_output_bytes: usize,
    ) -> Result<PairingNativeCommandOutput, PairingError> {
        self.calls.lock().expect("calls").push(RunCall {
            command: command.clone(),
            timeout,
            maximum_output_bytes,
        });
        self.outputs
            .lock()
            .expect("outputs")
            .pop_front()
            .unwrap_or(Err(PairingError::DirectLinkUnavailable))
    }

    // Rejects accidental publisher construction in direct-link tests.
    fn spawn(
        &self,
        _command: &PairingNativeCommand,
    ) -> Result<Box<dyn PairingNativeProcess>, PairingError> {
        Err(PairingError::DiscoveryUnavailable)
    }
}

// Returns one complete live ConnectX sysfs fixture and its provider.
fn fixture(
    route: Result<PairingNativeCommandOutput, PairingError>,
) -> (LinuxPairingDirectLinkProvider, Arc<MockIo>, Arc<MockRunner>) {
    let io = Arc::new(MockIo::default());
    for path in [
        "/sys/class/net/enp1s0",
        "/sys/class/infiniband",
        "/sys/class/infiniband/mlx5_0/device/net/enp1s0",
    ] {
        io.set_directory(path, true);
    }
    io.set_entries("/sys/class/infiniband", &["mlx5_0"]);
    io.set_value("/sys/class/net/enp1s0/carrier", b"1\n");
    io.set_value("/sys/class/net/enp1s0/operstate", b"up\n");
    io.set_value("/sys/class/net/enp1s0/speed", b"200000\n");
    io.set_value("/sys/class/net/enp1s0/mtu", b"9000\n");
    io.set_canonical(
        "/sys/class/net/enp1s0/device/driver",
        "/sys/bus/pci/drivers/mlx5_core",
    );
    let runner = Arc::new(MockRunner::default());
    runner.push(route);
    let provider = LinuxPairingDirectLinkProvider::new(
        PathBuf::from("/sys/class"),
        PathBuf::from("/usr/sbin/ip"),
        io.clone(),
        runner.clone(),
    )
    .expect("provider");
    (provider, io, runner)
}

// Returns one successful direct route command result.
fn direct_route() -> PairingNativeCommandOutput {
    PairingNativeCommandOutput::new(
        0,
        b"192.168.10.2 dev enp1s0 src 192.168.10.1 uid 501\n".to_vec(),
        Vec::new(),
        false,
    )
}

// Proves live mlx5/RDMA identity and executes one exact gateway-free route command.
#[test]
fn linux_direct_link_verifies_hardware_and_exact_route_command() {
    let (provider, _, runner) = fixture(Ok(direct_route()));
    provider
        .verify(
            &NetworkInterfaceName::parse("enp1s0").expect("interface"),
            &NodeAddress::parse("192.168.10.2").expect("peer"),
        )
        .expect("direct link");
    let calls = runner.calls.lock().expect("calls");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].command.executable(), Path::new("/usr/sbin/ip"));
    assert_eq!(
        calls[0].command.arguments(),
        ["-oneline", "route", "get", "192.168.10.2"]
    );
    assert_eq!(calls[0].timeout, Duration::from_secs(3));
    assert_eq!(calls[0].maximum_output_bytes, 8 * 1024);
}

// Rejects missing RDMA, dead carrier, and non-mlx5 hardware before any route query.
#[test]
fn linux_direct_link_rejects_invalid_hardware_boundaries() {
    for mutation in ["rdma", "carrier", "driver"] {
        let (provider, io, runner) = fixture(Ok(direct_route()));
        match mutation {
            "rdma" => io.set_directory("/sys/class/infiniband/mlx5_0/device/net/enp1s0", false),
            "carrier" => io.set_value("/sys/class/net/enp1s0/carrier", b"0\n"),
            "driver" => io.set_canonical(
                "/sys/class/net/enp1s0/device/driver",
                "/sys/bus/pci/drivers/igc",
            ),
            _ => unreachable!(),
        }
        assert_eq!(
            provider
                .verify(
                    &NetworkInterfaceName::parse("enp1s0").expect("interface"),
                    &NodeAddress::parse("192.168.10.2").expect("peer"),
                )
                .expect_err("hardware mutation must fail"),
            PairingError::DirectLinkUnavailable
        );
        assert!(runner.calls.lock().expect("calls").is_empty());
    }
}

// Rejects gateway routes, ambiguous output, timeout, and native command failure.
#[test]
fn linux_direct_link_rejects_unproven_route_results() {
    let results = [
        Ok(PairingNativeCommandOutput::new(
            0,
            b"192.168.10.2 via 192.168.10.1 dev enp1s0\n".to_vec(),
            Vec::new(),
            false,
        )),
        Ok(PairingNativeCommandOutput::new(
            0,
            b"192.168.10.2 dev enp1s0\n192.168.10.2 dev enp2s0\n".to_vec(),
            Vec::new(),
            false,
        )),
        Ok(PairingNativeCommandOutput::new(
            -1,
            Vec::new(),
            Vec::new(),
            true,
        )),
        Err(PairingError::DiscoveryUnavailable),
    ];
    for result in results {
        let (provider, _, _) = fixture(result);
        assert_eq!(
            provider
                .verify(
                    &NetworkInterfaceName::parse("enp1s0").expect("interface"),
                    &NodeAddress::parse("192.168.10.2").expect("peer"),
                )
                .expect_err("unproven route must fail"),
            PairingError::DirectLinkUnavailable
        );
    }
}

// Rejects hostnames, unsafe peers, relative sysfs roots, and relative native commands.
#[test]
fn linux_direct_link_validates_all_composition_inputs() {
    for peer in ["child.local", "127.0.0.1", "0.0.0.0"] {
        let (provider, _, runner) = fixture(Ok(direct_route()));
        assert_eq!(
            provider
                .verify(
                    &NetworkInterfaceName::parse("enp1s0").expect("interface"),
                    &NodeAddress::parse(peer).expect("peer"),
                )
                .expect_err("unsafe peer must fail"),
            PairingError::DirectLinkUnavailable
        );
        assert!(runner.calls.lock().expect("calls").is_empty());
    }
    let io = Arc::new(MockIo::default());
    let runner = Arc::new(MockRunner::default());
    assert!(LinuxPairingDirectLinkProvider::new(
        PathBuf::from("sys/class"),
        PathBuf::from("/usr/sbin/ip"),
        io.clone(),
        runner.clone(),
    )
    .is_err());
    assert!(LinuxPairingDirectLinkProvider::new(
        PathBuf::from("/sys/class"),
        PathBuf::from("ip"),
        io,
        runner,
    )
    .is_err());
}
