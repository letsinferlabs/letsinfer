#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

installer_cargo_command=""
installer_mktemp_command=""
installer_rm_command=""
installer_swiftc_command=""


# Ends the test lifecycle with one concise failure message.
fail() {
    printf 'li_installer tests: %s\n' "$*" >&2
    exit 1
}

# Parses the complete native test dependency contract.
parse_arguments() {
    while [ "$#" -gt 0 ]; do
        [ "$#" -ge 2 ] || fail "argument requires a value: $1"
        case "$1" in
            --cargo-command) installer_cargo_command=$2 ;;
            --mktemp-command) installer_mktemp_command=$2 ;;
            --rm-command) installer_rm_command=$2 ;;
            --swiftc-command) installer_swiftc_command=$2 ;;
            *) fail "unknown argument: $1" ;;
        esac
        shift 2
    done
}

# Validates one explicitly injected test command.
validate_command() {
    [ -n "$1" ] && [ "${1#/}" != "$1" ] && [ -x "$1" ] \
        || fail "test command is not an absolute executable: $1"
}

# Resolves repository and test roots without assuming the caller's directory.
resolve_roots() {
    case "$0" in
        */*) installer_test_parent=${0%/*} ;;
        *) installer_test_parent=. ;;
    esac
    installer_test_root=$(CDPATH= cd -P -- "$installer_test_parent" && pwd) \
        || fail "cannot resolve test root"
    installer_root=$(CDPATH= cd -P -- "$installer_test_root/../.." && pwd) \
        || fail "cannot resolve repository root"
}

# Builds and runs every locked Rust validator test with warnings denied.
run_validator_tests() {
    CARGO_TARGET_DIR="$installer_temporary_root/li_installer_validator_target" \
    RUSTFLAGS='-D warnings' "$installer_cargo_command" test \
        --manifest-path "$installer_test_root/validator/Cargo.toml" \
        --all-targets \
        --locked
    CARGO_TARGET_DIR="$installer_temporary_root/li_installer_validator_target" \
    RUSTFLAGS='-D warnings' "$installer_cargo_command" build \
        --manifest-path "$installer_test_root/validator/Cargo.toml" \
        --bin li_installer_validate \
        --locked
    installer_validator="$installer_temporary_root/li_installer_validator_target/debug/li_installer_validate"
    [ -x "$installer_validator" ] || fail "Rust validator binary is unavailable"
}

# Builds and tests both native Rust installer components through Cargo.
build_rust_installer() {
    CARGO_TARGET_DIR="$installer_temporary_root/li_installer_target" \
    RUSTFLAGS='-D warnings' "$installer_cargo_command" test \
        --manifest-path "$installer_root/li_installer/Cargo.toml" \
        --all-targets \
        --locked
    CARGO_TARGET_DIR="$installer_temporary_root/li_installer_target" \
    RUSTFLAGS='-D warnings' "$installer_cargo_command" build \
        --manifest-path "$installer_root/li_installer/Cargo.toml" \
        --bins \
        --locked
    installer_linux_probe="$installer_temporary_root/li_installer_target/debug/li_installer_installation_probe"
    installer_dependency_manager="$installer_temporary_root/li_installer_target/debug/li_installer_dependency_manager"
    [ -x "$installer_linux_probe" ] || fail "Linux installation probe is unavailable"
    [ -x "$installer_dependency_manager" ] || fail "dependency manager is unavailable"
}

# Builds the temporary native macOS provider when Swift is available.
build_macos_installer() {
    [ -n "$installer_swiftc_command" ] || return 0
    validate_command "$installer_swiftc_command"
    installer_macos_probe="$installer_temporary_root/li_installer_installation_probe_macos"
    "$installer_swiftc_command" \
        -O \
        -warnings-as-errors \
        -framework Metal \
        "$installer_root/li_installer/macos/li_installer_installation_probe.swift" \
        -o "$installer_macos_probe"
}

# Extracts the inlined display manager for isolated presentation tests.
extract_display_manager() {
    installer_display_manager="$installer_temporary_root/li_installer_display_manager.sh"
    installer_display_capture=0
    installer_display_complete=0
    : >"$installer_display_manager"
    while IFS= read -r installer_display_line \
        || [ -n "$installer_display_line" ]; do
        case "$installer_display_line" in
            "# BEGIN DISPLAY MANAGER") installer_display_capture=1 ;;
            "# END DISPLAY MANAGER")
                installer_display_complete=1
                break
                ;;
            *)
                if [ "$installer_display_capture" -eq 1 ]; then
                    printf '%s\n' "$installer_display_line" >>"$installer_display_manager"
                fi
                ;;
        esac
    done <"$installer_root/install.sh"
    [ "$installer_display_capture" -eq 1 ] \
        && [ "$installer_display_complete" -eq 1 ] \
        || fail "inlined display manager is unavailable"
}

# Exercises interactive and machine-oriented display contracts in isolation.
run_display_manager_tests() {
    extract_display_manager
    installer_display_output=$(
        (
            . "$installer_display_manager"
            display_manager_configure 1 en_US.UTF-8 0 1
            display_manager_present_progress 5 "Inspecting platform"
            display_manager_finish_progress
            display_manager_present_completion 1.0.0 installed linux arm64
        ) 2>&1
    )
    case "$installer_display_output" in
        *"ϟ  LET'S INFER"*"INSTALL"*"Inspecting platform"*"Complete"*\
"✓  Let's Infer 1.0.0 installed"*"linux/arm64"*) ;;
        *) fail "interactive display contract is invalid" ;;
    esac

    installer_display_failure=$(
        (
            . "$installer_display_manager"
            display_manager_configure 1 C 0 1
            display_manager_present_failure "fixture failure"
        ) 2>&1
    )
    case "$installer_display_failure" in
        *">  LET'S INFER"*"x  Installation failed"*"fixture failure"*) ;;
        *) fail "failure display contract is invalid" ;;
    esac

    installer_display_output=$(
        (
            . "$installer_display_manager"
            display_manager_configure 0 en_US.UTF-8 0 1
            display_manager_present_progress 5 "Inspecting platform"
            display_manager_finish_progress
            display_manager_present_completion 1.0.0 installed linux arm64
        ) 2>&1
    )
    [ "$installer_display_output" = \
        "Let's Infer 1.0.0 installed for linux/arm64." ] \
        || fail "machine-oriented display contract is invalid"
}

# Requires one native component to emit exactly one expected semantic event.
validate_component_event_file() {
    "$installer_validator" --event "$2" "$1"
}

# Validates one generated fixture document with the test-owned Rust validator.
validate_fixture_document() {
    "$installer_validator" "$installer_schema" "$1"
}

# Runs the macOS ARM64 probe entirely through injected fixture dependencies.
run_mock_macos_probe() {
    [ -n "$installer_swiftc_command" ] || return 0
    installer_mock_root="$installer_test_root/fixtures/li_installer_macos_arm64"
    installer_output="$installer_temporary_root/li_installer_macos_arm64.json"
    installer_error="$installer_temporary_root/li_installer_macos_arm64.stderr"

    "$installer_macos_probe" \
        --platform macos-arm64 \
        --mode fixture \
        --schema-file "$installer_schema" \
        --status ready \
        --missing-dependencies "" \
        --service-manager-provider launchd \
        --service-manager-scope gui \
        --service-manager-user-domain-available true \
        --service-persistence-mechanism launch-agent \
        --service-persistence-available true \
        --dependency "curl=$installer_mock_root/bin/date" \
        --dependency "mktemp=$installer_mock_root/bin/date" \
        --dependency "openssl=$installer_mock_root/bin/date" \
        --dependency "python=$installer_mock_root/bin/date" \
        --dependency "ssh=$installer_mock_root/bin/date" \
        --dependency "ssh_keygen=$installer_mock_root/bin/date" \
        --dependency "sudo=$installer_mock_root/bin/date" \
        --dependency "tar=$installer_mock_root/bin/date" \
        --dependency "brew=" \
        --dependency "launchctl=$installer_mock_root/bin/date" \
        --dependency "sw_vers=$installer_mock_root/bin/sw_vers" \
        --dependency "sysctl=$installer_mock_root/bin/sysctl" \
        --dependency "system_profiler=$installer_mock_root/bin/system_profiler" \
        --installable-dependency openssl \
        --installable-dependency python \
        --date-command "$installer_mock_root/bin/date" \
        --uname-command "$installer_mock_root/bin/uname" \
        --sysctl-command "$installer_mock_root/bin/sysctl" \
        --sw-vers-command "$installer_mock_root/bin/sw_vers" \
        --system-profiler-command "$installer_mock_root/bin/system_profiler" \
        --metal-observation-source fixture \
        --metal-observation-file "$installer_mock_root/li_installer_metal_observation.json" \
        >"$installer_output" \
        2>"$installer_error"

    validate_component_event_file \
        "$installer_error" \
        "letsinfer.event=platform_probe_complete"
    validate_fixture_document "$installer_output"
}

# Runs one Linux fixture through every injected file and command dependency.
run_mock_linux_probe() {
    installer_mock_name=$1
    installer_platform=$2
    installer_mock_root="$installer_test_root/fixtures/$installer_mock_name"
    installer_output="$installer_temporary_root/$installer_mock_name.json"
    installer_error="$installer_temporary_root/$installer_mock_name.stderr"

    "$installer_linux_probe" \
        --platform "$installer_platform" \
        --mode fixture \
        --schema-file "$installer_schema" \
        --status missing_dependencies \
        --missing-dependencies "avahi_browse,avahi_publish_service,cc,cmake,ctest" \
        --service-manager-provider systemd \
        --service-manager-scope user \
        --service-manager-user-domain-available true \
        --service-persistence-mechanism systemd-linger \
        --service-persistence-available true \
        --dependency "curl=$installer_mock_root/bin/date" \
        --dependency "mktemp=$installer_mock_root/bin/date" \
        --dependency "openssl=$installer_mock_root/bin/date" \
        --dependency "python=$installer_mock_root/bin/date" \
        --dependency "ssh=$installer_mock_root/bin/date" \
        --dependency "ssh_keygen=$installer_mock_root/bin/date" \
        --dependency "sudo=$installer_mock_root/bin/date" \
        --dependency "tar=$installer_mock_root/bin/date" \
        --dependency "apt_get=$installer_mock_root/bin/apt-get" \
        --dependency "avahi_browse=" \
        --dependency "avahi_publish_service=" \
        --dependency "cc=" \
        --dependency "cmake=" \
        --dependency "ctest=" \
        --dependency "dnf=" \
        --dependency "docker=$installer_mock_root/bin/docker" \
        --dependency "loginctl=$installer_mock_root/bin/date" \
        --dependency "nvidia_ctk=$installer_mock_root/bin/nvidia-ctk" \
        --dependency "nvidia_smi=$installer_mock_root/bin/nvidia-smi" \
        --dependency "pacman=" \
        --dependency "sg=" \
        --dependency "stat=" \
        --dependency "systemctl=$installer_mock_root/bin/date" \
        --dependency "systemd_run=$installer_mock_root/bin/date" \
        --dependency "zypper=" \
        --installable-dependency avahi_browse \
        --installable-dependency avahi_publish_service \
        --installable-dependency cc \
        --installable-dependency cmake \
        --installable-dependency ctest \
        --installable-dependency docker \
        --installable-dependency nvidia_ctk \
        --installable-dependency openssl \
        --installable-dependency python \
        --installable-dependency ssh \
        --date-command "$installer_mock_root/bin/date" \
        --uname-command "$installer_mock_root/bin/uname" \
        --getconf-command "$installer_mock_root/bin/getconf" \
        --os-release-file "$installer_mock_root/root/etc/os-release" \
        --meminfo-file "$installer_mock_root/root/proc/meminfo" \
        --cpuinfo-file "$installer_mock_root/root/proc/cpuinfo" \
        --boot-id-file "$installer_mock_root/root/proc/sys/kernel/random/boot_id" \
        --lscpu-command "$installer_mock_root/bin/lscpu" \
        --nvidia-smi-command "$installer_mock_root/bin/nvidia-smi" \
        --docker-command "$installer_mock_root/bin/docker" \
        --nvidia-ctk-command "$installer_mock_root/bin/nvidia-ctk" \
        >"$installer_output" \
        2>"$installer_error"

    validate_component_event_file \
        "$installer_error" \
        "letsinfer.event=platform_probe_complete"
    validate_fixture_document "$installer_output"
    run_mock_dependency_manager "$installer_mock_root" "$installer_output"
}

# Applies and verifies one injected dependency-manager package transaction.
run_mock_dependency_manager() {
    installer_manager_mock_root=$1
    installer_manager_probe=$2
    installer_manager_result="$installer_manager_probe.manager_result"
    installer_manager_error="$installer_manager_probe.manager_error"

    "$installer_dependency_manager" \
        --mode apply \
        --probe-file "$installer_manager_probe" \
        --id-command "$installer_manager_mock_root/bin/id" \
        >"$installer_manager_result" \
        2>"$installer_manager_error"
    validate_component_event_file \
        "$installer_manager_error" \
        "letsinfer.event=dependencies_installed"
    installer_manager_first_line=""
    IFS= read -r installer_manager_first_line <"$installer_manager_result" || true
    [ "$installer_manager_first_line" = installed ] \
        || fail "mock dependency manager did not install its package plan"

    set +e
    "$installer_dependency_manager" \
        --mode verify \
        --probe-file "$installer_manager_probe" \
        --id-command "$installer_manager_mock_root/bin/id" \
        >"$installer_manager_result" \
        2>"$installer_manager_error"
    installer_manager_status=$?
    set -e
    [ "$installer_manager_status" -eq 1 ] \
        || fail "stale dependency verification did not fail"
    installer_manager_first_line=""
    IFS= read -r installer_manager_first_line <"$installer_manager_error" || true
    case "$installer_manager_first_line" in
        "dependency manager: installable dependencies remain unavailable:"*) ;;
        *) fail "stale dependency verification reason is invalid" ;;
    esac
}

# Runs every native installer mock and validator contract.
main() {
    parse_arguments "$@"
    validate_command "$installer_cargo_command"
    validate_command "$installer_mktemp_command"
    validate_command "$installer_rm_command"
    resolve_roots

    installer_schema="$installer_root/schemas/li_installer_installation_probe_v1.schema.json"
    installer_temporary_root=$(
        "$installer_mktemp_command" -d /tmp/li_installer_tests.XXXXXXXX
    ) || fail "cannot create temporary test root"
    trap '"$installer_rm_command" -rf -- "$installer_temporary_root"' EXIT HUP INT TERM

    run_validator_tests
    run_display_manager_tests
    build_rust_installer
    build_macos_installer
    run_mock_macos_probe
    run_mock_linux_probe li_installer_linux_arm64 linux-arm64
    run_mock_linux_probe li_installer_linux_x86_64 linux-x86_64
    printf 'li_installer tests: PASS\n'
}

main "$@"
