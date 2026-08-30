#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

installer_cargo_command=""
installer_mktemp_command=""
installer_rm_command=""
installer_swiftc_command=""

# Ends the native installer test lifecycle with one concise failure.
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

# Builds and runs every locked Rust validator contract with warnings denied.
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

# Builds and runs the complete internal Rust installer contract.
run_rust_installer_tests() {
    CARGO_TARGET_DIR="$installer_temporary_root/li_installer_target" \
    LI_INSTALLER_TEST_SCHEMA="$installer_schema" \
    LI_INSTALLER_TEST_VALIDATOR="$installer_validator" \
    RUSTFLAGS='-D warnings' "$installer_cargo_command" test \
        --manifest-path "$installer_root/installer/Cargo.toml" \
        --all-targets \
        --locked
}

# Builds and runs the macOS Swift provider through deterministic native fixtures.
run_macos_provider_test() {
    [ -n "$installer_swiftc_command" ] || return 0
    validate_command "$installer_swiftc_command"
    installer_fixture="$installer_test_root/fixtures/li_installer_macos_arm64"
    installer_probe="$installer_temporary_root/li_installer_macos_probe"
    installer_output="$installer_temporary_root/li_installer_macos_arm64.json"
    installer_error="$installer_temporary_root/li_installer_macos_arm64.stderr"
    "$installer_swiftc_command" \
        -O \
        -warnings-as-errors \
        -framework Metal \
        "$installer_root/installer/macos/li_installer_macos_probe.swift" \
        -o "$installer_probe"
    "$installer_probe" \
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
        --dependency "curl=$installer_fixture/bin/date" \
        --dependency "gh=$installer_fixture/bin/date" \
        --dependency "mktemp=$installer_fixture/bin/date" \
        --dependency "openssl=$installer_fixture/bin/date" \
        --dependency "ssh=$installer_fixture/bin/date" \
        --dependency "ssh_keygen=$installer_fixture/bin/date" \
        --dependency "sudo=$installer_fixture/bin/date" \
        --dependency "tar=$installer_fixture/bin/date" \
        --dependency "brew=" \
        --dependency "launchctl=$installer_fixture/bin/date" \
        --dependency "sw_vers=$installer_fixture/bin/sw_vers" \
        --dependency "sysctl=$installer_fixture/bin/sysctl" \
        --dependency "system_profiler=$installer_fixture/bin/system_profiler" \
        --installable-dependency openssl \
        --date-command "$installer_fixture/bin/date" \
        --uname-command "$installer_fixture/bin/uname" \
        --sysctl-command "$installer_fixture/bin/sysctl" \
        --sw-vers-command "$installer_fixture/bin/sw_vers" \
        --system-profiler-command "$installer_fixture/bin/system_profiler" \
        --metal-observation-source fixture \
        --metal-observation-file "$installer_fixture/li_installer_metal_observation.json" \
        >"$installer_output" \
        2>"$installer_error"
    [ ! -s "$installer_error" ] || fail "macOS provider wrote diagnostics"
    "$installer_validator" "$installer_schema" "$installer_output"
}

# Runs every native installer, provider, and validator contract.
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
    run_rust_installer_tests
    run_macos_provider_test
    printf 'li_installer tests: PASS\n'
}

main "$@"
