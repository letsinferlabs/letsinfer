// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use li_core_application::{
    CoreProcessContractError, CoreProcessLayout, CoreProcessPlatform, CoreResidentProcess,
};

// Prevents the resident process from regressing to the retired fail-closed pairing placeholder.
#[test]
fn node_process_composes_the_production_pairing_api() {
    let source = include_str!("../src/li_core_node_process.rs");
    assert!(source.contains("compose_core_node_pairing_api("));
    assert!(!source.contains("UnavailableNodePairingApi"));
}

// Resolves every Linux resident process in the exact startup and naming contract.
#[test]
fn linux_layout_resolves_three_fixed_shell_free_commands() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer/core/versions/1.0.0/identity"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    let commands = layout.commands().expect("commands");
    assert_eq!(commands.len(), 3);
    assert_eq!(
        commands
            .iter()
            .map(|command| command.process())
            .collect::<Vec<_>>(),
        [
            CoreResidentProcess::Node,
            CoreResidentProcess::Watchdog,
            CoreResidentProcess::Gateway,
        ]
    );
    assert_eq!(commands[0].service_identity(), "li_node.service");
    assert_eq!(
        commands[0].executable(),
        Path::new("/opt/letsinfer/core/versions/1.0.0/identity/bin/li_node")
    );
    assert_eq!(
        commands[0].arguments(),
        [
            OsString::from("--configuration"),
            OsString::from("/var/lib/letsinfer/configuration/li_node.json"),
        ]
    );
    assert_eq!(commands[0].standard_output(), None);
    assert_eq!(commands[0].standard_error(), None);
}

// Resolves macOS supervision without fabricating a separate Watchdog process.
#[test]
fn macos_layout_uses_two_launchd_processes() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Macos,
        PathBuf::from("/Users/taimur/.letsinfer/core/current"),
        PathBuf::from("/Users/taimur/.letsinfer/configuration"),
        PathBuf::from("/Users/taimur/.letsinfer/logs"),
    )
    .expect("layout");
    let commands = layout.commands().expect("commands");
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].service_identity(), "ai.letsinfer.node");
    assert_eq!(commands[1].service_identity(), "ai.letsinfer.gateway");
    assert_eq!(
        commands[0].standard_output(),
        Some(Path::new("/Users/taimur/.letsinfer/logs/li_node.log"))
    );
    assert_eq!(
        commands[1].standard_error(),
        Some(Path::new(
            "/Users/taimur/.letsinfer/logs/li_gateway.error.log"
        ))
    );
    assert_eq!(
        layout.command(CoreResidentProcess::Watchdog),
        Err(CoreProcessContractError::UnsupportedProcess)
    );
}

// Rejects relative, normalized-parent, root-only, equal, and nested root configurations.
#[test]
fn unsafe_or_ambiguous_roots_fail_before_resolution() {
    for (installation, configuration, logs, expected) in [
        (
            PathBuf::from("relative/core"),
            PathBuf::from("/private/configuration"),
            PathBuf::from("/private/logs"),
            CoreProcessContractError::UnsafePath,
        ),
        (
            PathBuf::from("/private/../core"),
            PathBuf::from("/private/configuration"),
            PathBuf::from("/private/logs"),
            CoreProcessContractError::UnsafePath,
        ),
        (
            PathBuf::from("/"),
            PathBuf::from("/private/configuration"),
            PathBuf::from("/private/logs"),
            CoreProcessContractError::UnsafePath,
        ),
        (
            PathBuf::from("/private/core"),
            PathBuf::from("/private/core"),
            PathBuf::from("/private/logs"),
            CoreProcessContractError::AmbiguousRoots,
        ),
        (
            PathBuf::from("/private/core"),
            PathBuf::from("/private/core/configuration"),
            PathBuf::from("/private/logs"),
            CoreProcessContractError::AmbiguousRoots,
        ),
        (
            PathBuf::from("/private/core"),
            PathBuf::from("/private/configuration"),
            PathBuf::from("/private/configuration/logs"),
            CoreProcessContractError::AmbiguousRoots,
        ),
    ] {
        assert_eq!(
            CoreProcessLayout::new(
                CoreProcessPlatform::Linux,
                installation,
                configuration,
                logs,
            ),
            Err(expected)
        );
    }
}
