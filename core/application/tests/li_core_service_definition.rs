// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

use li_core_application::{
    CoreProcessLayout, CoreProcessPlatform, CoreResidentProcess, CoreServiceDefinitionProvider,
};
use li_core_interface::Sha256Digest;
use sha2::{Digest, Sha256};

// Generates independently restartable Linux residents under one exact immutable installation.
#[test]
fn linux_service_set_is_complete_distinct_and_restart_consistent() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer/core/versions/1.0.0/identity"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    let definitions = layout
        .commands()
        .expect("commands")
        .iter()
        .map(|command| {
            CoreServiceDefinitionProvider
                .definition(CoreProcessPlatform::Linux, command)
                .expect("definition")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.filename())
            .collect::<Vec<_>>(),
        [
            "li_node.service",
            "li_watchdog.service",
            "li_gateway.service",
        ]
    );
    let identities = definitions
        .iter()
        .map(|definition| definition.sha256().as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(identities.len(), definitions.len());
    for definition in definitions {
        let text = std::str::from_utf8(definition.bytes()).expect("UTF-8");
        assert_eq!(text.matches("Restart=always").count(), 1);
        assert_eq!(text.matches("StartLimitIntervalSec=0").count(), 1);
        assert_eq!(text.matches("MemoryAccounting=true").count(), 1);
        assert_eq!(text.matches("NoNewPrivileges=true").count(), 1);
        assert_eq!(text.matches("LockPersonality=true").count(), 1);
        assert_eq!(text.matches("MemoryDenyWriteExecute=true").count(), 1);
        assert_eq!(text.matches("RestrictRealtime=true").count(), 1);
        assert_eq!(text.matches("SystemCallArchitectures=native").count(), 1);
        assert_eq!(text.matches("UMask=0077").count(), 1);
        assert_eq!(text.matches("ExecStart=").count(), 1);
        assert!(!text.contains("ExecStartPre="));
        assert!(!text.contains("ExecStartPost="));
        assert!(!text.contains("Restart=on-failure"));
        assert!(!text.contains("Requires="));
        assert!(!text.contains("PartOf="));
        assert!(!text.contains("BindsTo="));
    }
}

// Orders safety dependencies without making independently supervised residents restart together.
#[test]
fn linux_service_dependency_graph_starts_safety_before_public_traffic() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer/core"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    for (process, expected_after, expected_wants, forbidden) in [
        (
            CoreResidentProcess::Node,
            "After=network-online.target",
            "Wants=network-online.target",
            &[
                "li_node.service",
                "li_watchdog.service",
                "li_gateway.service",
            ][..],
        ),
        (
            CoreResidentProcess::Watchdog,
            "After=network-online.target li_node.service",
            "Wants=network-online.target li_node.service",
            &["li_watchdog.service", "li_gateway.service"][..],
        ),
        (
            CoreResidentProcess::Gateway,
            "After=network-online.target li_node.service li_watchdog.service",
            "Wants=network-online.target li_node.service li_watchdog.service",
            &["li_gateway.service"][..],
        ),
    ] {
        let command = layout.command(process).expect("command");
        let definition = CoreServiceDefinitionProvider
            .definition(CoreProcessPlatform::Linux, &command)
            .expect("definition");
        let text = std::str::from_utf8(definition.bytes()).expect("UTF-8");
        assert_eq!(text.matches(expected_after).count(), 1);
        assert_eq!(text.matches(expected_wants).count(), 1);
        assert!(!text.contains("Requires="));
        assert!(!text.contains("PartOf="));
        for identity in forbidden {
            assert!(!text.contains(identity));
        }
    }
}

// Gives only the Node process netlink access while preserving shared local and network sockets.
#[test]
fn linux_service_socket_families_follow_each_process_responsibility() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer/core"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    for process in [
        CoreResidentProcess::Node,
        CoreResidentProcess::Gateway,
        CoreResidentProcess::Watchdog,
    ] {
        let command = layout.command(process).expect("command");
        let definition = CoreServiceDefinitionProvider
            .definition(CoreProcessPlatform::Linux, &command)
            .expect("definition");
        let text = std::str::from_utf8(definition.bytes()).expect("UTF-8");
        let expected = match process {
            CoreResidentProcess::Node => {
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
            }
            CoreResidentProcess::Gateway | CoreResidentProcess::Watchdog => {
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"
            }
        };
        assert_eq!(text.matches(expected).count(), 1);
        if process != CoreResidentProcess::Node {
            assert!(!text.contains("AF_NETLINK"));
        }
    }
}

// Preserves the established per-process memory, task, descriptor, and scheduling envelopes.
#[test]
fn linux_service_resource_profiles_match_the_existing_resident_contracts() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer/core"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    for (process, required, forbidden) in [
        (
            CoreResidentProcess::Node,
            &[
                "MemoryHigh=134217728",
                "MemoryMax=201326592",
                "MemorySwapMax=0",
                "TasksMax=32",
                "LimitNOFILE=128",
                "RestartSec=2s",
                "TimeoutStopSec=15s",
            ][..],
            &[
                "Nice=10",
                "CPUWeight=1",
                "IOWeight=1",
                "IOSchedulingClass=idle",
            ][..],
        ),
        (
            CoreResidentProcess::Gateway,
            &[
                "MemoryHigh=67108864",
                "MemoryMax=100663296",
                "MemorySwapMax=0",
                "RestartSec=2s",
                "TimeoutStopSec=30s",
            ][..],
            &[
                "TasksMax=",
                "LimitNOFILE=",
                "Nice=10",
                "CPUWeight=1",
                "IOWeight=1",
                "IOSchedulingClass=idle",
            ][..],
        ),
        (
            CoreResidentProcess::Watchdog,
            &[
                "MemoryHigh=25165824",
                "MemoryMax=31457280",
                "MemorySwapMax=0",
                "TasksMax=8",
                "LimitNOFILE=64",
                "Nice=10",
                "CPUWeight=1",
                "IOWeight=1",
                "IOSchedulingClass=idle",
                "RestartSec=5s",
                "TimeoutStopSec=30s",
            ][..],
            &["TasksMax=32", "LimitNOFILE=128"][..],
        ),
    ] {
        let command = layout.command(process).expect("command");
        let definition = CoreServiceDefinitionProvider
            .definition(CoreProcessPlatform::Linux, &command)
            .expect("definition");
        let text = std::str::from_utf8(definition.bytes()).expect("UTF-8");
        for directive in required {
            assert_eq!(
                text.matches(directive).count(),
                1,
                "{process:?} must contain {directive} exactly once"
            );
        }
        for directive in forbidden {
            assert!(
                !text.contains(directive),
                "{process:?} must not inherit {directive}"
            );
        }
    }
}

// Generates deterministic systemd units whose identities bind their exact command bytes.
#[test]
fn linux_definition_is_shell_free_content_addressed_and_private() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/Let's Infer/core%1"),
        PathBuf::from("/var/lib/Let's Infer/configuration"),
        PathBuf::from("/var/lib/Let's Infer/logs"),
    )
    .expect("layout");
    let command = layout.command(CoreResidentProcess::Node).expect("command");
    let definition = CoreServiceDefinitionProvider
        .definition(CoreProcessPlatform::Linux, &command)
        .expect("definition");
    let text = String::from_utf8(definition.bytes().to_vec()).expect("UTF-8");
    assert_eq!(definition.filename(), "li_node.service");
    assert_eq!(definition.mode(), 0o600);
    assert!(text.contains(
        "ExecStart=\"/opt/Let's Infer/core%%1/bin/li_node\" \"--configuration\" \"/var/lib/Let's Infer/configuration/li_node.json\""
    ));
    assert!(!text.contains("/bin/sh"));
    assert!(!text.contains("Environment="));
    assert_eq!(
        definition.sha256(),
        &Sha256Digest::parse(&format!("{:x}", Sha256::digest(definition.bytes()))).expect("digest")
    );
}

// Generates a closed launchd argument array with exact XML escaping and no shell string.
#[test]
fn macos_definition_uses_one_escaped_program_argument_array() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Macos,
        PathBuf::from("/Users/taimur/Let's & Infer/core"),
        PathBuf::from("/Users/taimur/Let's & Infer/configuration"),
        PathBuf::from("/Users/taimur/Let's & Infer/logs"),
    )
    .expect("layout");
    let command = layout
        .command(CoreResidentProcess::Gateway)
        .expect("command");
    let definition = CoreServiceDefinitionProvider
        .definition(CoreProcessPlatform::Macos, &command)
        .expect("definition");
    let text = String::from_utf8(definition.bytes().to_vec()).expect("UTF-8");
    assert_eq!(definition.filename(), "ai.letsinfer.gateway.plist");
    assert!(text.contains("<string>ai.letsinfer.gateway</string>"));
    assert!(
        text.contains("<string>/Users/taimur/Let&apos;s &amp; Infer/core/bin/li_gateway</string>")
    );
    assert!(text.contains(
        "<key>StandardOutPath</key>\n  <string>/Users/taimur/Let&apos;s &amp; Infer/logs/li_gateway.log</string>"
    ));
    assert!(text.contains(
        "<key>StandardErrorPath</key>\n  <string>/Users/taimur/Let&apos;s &amp; Infer/logs/li_gateway.error.log</string>"
    ));
    assert_eq!(text.matches("<key>ProgramArguments</key>").count(), 1);
    assert!(text.contains("<key>RunAtLoad</key>\n  <true/>"));
    assert!(text.contains("<key>KeepAlive</key>\n  <true/>"));
    assert!(text.contains("<key>ThrottleInterval</key>\n  <integer>2</integer>"));
    assert!(!text.contains("SuccessfulExit"));
    assert!(!text.contains("/bin/sh"));
}

// Rejects a definition request whose command belongs to another supervisor family.
#[test]
fn platform_identity_mismatch_fails_before_service_bytes_exist() {
    let linux = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer/core"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    let command = linux.command(CoreResidentProcess::Node).expect("command");
    assert!(CoreServiceDefinitionProvider
        .definition(CoreProcessPlatform::Macos, &command)
        .is_err());
}

// Escapes systemd quoting and specifier characters without changing argv boundaries.
#[test]
fn linux_definition_escapes_quotes_backslashes_and_specifiers() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/let\"s\\infer/core%2"),
        PathBuf::from("/var/lib/let\"s\\infer/configuration"),
        PathBuf::from("/var/lib/let\"s\\infer/logs"),
    )
    .expect("layout");
    let command = layout.command(CoreResidentProcess::Node).expect("command");
    let definition = CoreServiceDefinitionProvider
        .definition(CoreProcessPlatform::Linux, &command)
        .expect("definition");
    let text = std::str::from_utf8(definition.bytes()).expect("UTF-8");
    assert!(text.contains(
        "ExecStart=\"/opt/let\\\"s\\\\infer/core%%2/bin/li_node\" \"--configuration\" \"/var/lib/let\\\"s\\\\infer/configuration/li_node.json\""
    ));
    assert_eq!(text.matches("ExecStart=").count(), 1);
}

// Rejects control-bearing native arguments before serializing a supervisor document.
#[test]
fn control_bearing_service_paths_fail_before_definition_bytes_exist() {
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        PathBuf::from("/opt/letsinfer\ncore"),
        PathBuf::from("/var/lib/letsinfer/configuration"),
        PathBuf::from("/var/lib/letsinfer/logs"),
    )
    .expect("layout");
    let command = layout.command(CoreResidentProcess::Node).expect("command");
    assert!(CoreServiceDefinitionProvider
        .definition(CoreProcessPlatform::Linux, &command)
        .is_err());
}

// Requires every generated Linux unit to pass the native systemd verifier on Linux CI.
#[cfg(target_os = "linux")]
#[test]
fn linux_definitions_pass_native_systemd_verification() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().expect("temporary");
    let installation = temporary.path().join("installation");
    let configuration = temporary.path().join("configuration");
    fs::create_dir_all(installation.join("bin")).expect("binary directory");
    fs::create_dir_all(&configuration).expect("configuration directory");
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Linux,
        installation.clone(),
        configuration,
        temporary.path().join("logs"),
    )
    .expect("layout");
    for command in layout.commands().expect("commands") {
        fs::write(command.executable(), b"#!/bin/sh\nexit 0\n").expect("executable");
        fs::set_permissions(command.executable(), fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        let definition = CoreServiceDefinitionProvider
            .definition(CoreProcessPlatform::Linux, &command)
            .expect("definition");
        let path = temporary.path().join(definition.filename());
        fs::write(&path, definition.bytes()).expect("unit");
        let output = Command::new("/usr/bin/systemd-analyze")
            .args(["--user", "verify"])
            .arg(&path)
            .output()
            .expect("systemd verifier");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// Requires every generated macOS agent to pass Apple's native plist verifier on macOS CI.
#[cfg(target_os = "macos")]
#[test]
fn macos_definitions_pass_native_plist_verification() {
    use std::fs;

    let temporary = tempfile::tempdir().expect("temporary");
    let layout = CoreProcessLayout::new(
        CoreProcessPlatform::Macos,
        temporary.path().join("installation"),
        temporary.path().join("configuration"),
        temporary.path().join("logs"),
    )
    .expect("layout");
    for command in layout.commands().expect("commands") {
        let definition = CoreServiceDefinitionProvider
            .definition(CoreProcessPlatform::Macos, &command)
            .expect("definition");
        let path = temporary.path().join(definition.filename());
        fs::write(&path, definition.bytes()).expect("plist");
        let output = Command::new("/usr/bin/plutil")
            .args(["-lint", "--"])
            .arg(&path)
            .output()
            .expect("plist verifier");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
