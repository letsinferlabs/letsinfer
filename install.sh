#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

repository="letsinferlabs/letsinfer"
version=""
base_url=""
prefix=""
launcher_root="/usr/local/bin"
user_install=0
run_setup=1
repair_docker_access=0
progress_enabled=1
control_address=auto
temporary=""

# BEGIN DISPLAY MANAGER

display_manager_progress_active=0
display_manager_interactive=0
display_manager_brand_mark=">"
display_manager_failure_mark="x"
display_manager_badge_text=">  LET'S INFER"
display_manager_blue=""
display_manager_red=""
display_manager_reset=""

# Configures bootstrap presentation from terminal, locale, color, and progress facts.
display_manager_configure() {
    display_manager_requested_interactive=$1
    display_manager_locale=$2
    display_manager_color_enabled=$3
    display_manager_progress_enabled=$4
    case "$display_manager_requested_interactive/$display_manager_color_enabled/$display_manager_progress_enabled" in
        0/0/0|0/0/1|0/1/0|0/1/1|1/0/0|1/0/1|1/1/0|1/1/1) ;;
        *) return 1 ;;
    esac
    display_manager_interactive=$display_manager_requested_interactive
    if [ "$display_manager_interactive" -eq 1 ] \
        && [ "$display_manager_progress_enabled" -eq 1 ]; then
        display_manager_progress_active=1
    fi
    case "$display_manager_locale" in
        *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*)
            display_manager_brand_mark="ϟ"
            display_manager_failure_mark="✗"
            ;;
    esac
    if [ "$display_manager_interactive" -eq 1 ] \
        && [ "$display_manager_color_enabled" -eq 1 ]; then
        display_manager_reset=$(printf '\033[0m')
        display_manager_blue=$(printf '\033[1;38;2;0;156;223m')
        display_manager_red=$(printf '\033[1;38;2;226;56;56m')
        display_manager_badge_text=$(printf \
            '\033[1;38;2;30;30;30;48;2;247;247;247m %s  LET\047S INFER \033[0m' \
            "$display_manager_brand_mark")
    else
        display_manager_badge_text="$display_manager_brand_mark  LET'S INFER"
    fi
}

# Clears the active bootstrap progress row before another presentation replaces it.
display_manager_clear_progress() {
    if [ "$display_manager_progress_active" -eq 1 ]; then
        printf '\r\033[2K' >&2
    fi
}

# Presents one stable bootstrap stage before the native installer takes over.
display_manager_present_progress() {
    display_manager_percent=$1
    display_manager_message=$2
    if [ "$display_manager_progress_active" -eq 1 ]; then
        printf '\r\033[2K%s  %sINSTALL%s  %s%3s%%%s  %s' \
            "$display_manager_badge_text" "$display_manager_blue" \
            "$display_manager_reset" "$display_manager_blue" \
            "$display_manager_percent" "$display_manager_reset" \
            "$display_manager_message" >&2
    fi
}

# Presents one bootstrap failure through the shared installation vocabulary.
display_manager_present_failure() {
    display_manager_clear_progress
    display_manager_progress_active=0
    if [ "$display_manager_interactive" -eq 1 ]; then
        printf '%s  %sINSTALL%s\n\n%s%s  Installation failed%s\n   %s\n' \
            "$display_manager_badge_text" "$display_manager_red" \
            "$display_manager_reset" "$display_manager_red" \
            "$display_manager_failure_mark" "$display_manager_reset" "$*" >&2
    else
        printf 'letsinfer install: %s\n' "$*" >&2
    fi
}

# END DISPLAY MANAGER

# Prints the supported public bootstrap arguments and installation boundary.
usage() {
    cat <<'EOF'
Usage: install.sh [--version VERSION] [--prefix PATH] [--user] [--no-setup] [--no-progress]
                  [--repair-docker-access] [--control-address ADDRESS]

Download and start the verified native Let's Infer installer. The native
installer owns dependency setup, Core installation, services, and final output.
EOF
}

# Removes the exact temporary bootstrap root when native execution has not taken over.
cleanup() {
    display_manager_clear_progress
    if [ -n "$temporary" ]; then
        rm -rf -- "$temporary"
        temporary=""
    fi
}

# Ends bootstrap through the single configured display failure boundary.
fail() {
    display_manager_present_failure "$*"
    exit 1
}

# Downloads one bootstrap input after enforcing its approved URL scheme.
download() {
    source_url=$1
    output_path=$2
    case "$source_url" in
        https://*) ;;
        http://*|file://*)
            [ "$allow_insecure" = "1" ] || fail "release URL must use HTTPS"
            ;;
        *) fail "release URL is invalid" ;;
    esac
    "$curl_command" --fail --location --silent --show-error \
        --proto "$curl_protocols" --tlsv1.2 \
        --output "$output_path" "$source_url"
}

# Returns the SHA-256 digest of one regular file through a platform-native utility.
sha256_digest() {
    sha256_path=$1
    if [ -n "$sha256sum_command" ]; then
        "$sha256sum_command" "$sha256_path" | "$awk_command" '{print $1}'
    elif [ -n "$shasum_command" ]; then
        "$shasum_command" -a 256 "$sha256_path" | "$awk_command" '{print $1}'
    else
        "$openssl_command" dgst -sha256 -r "$sha256_path" | "$awk_command" '{print $1}'
    fi
}

# Verifies the selected native archive against the signed checksum document.
verify_native_checksum() {
    [ ! -L "$checksums" ] && [ -f "$checksums" ] || return 1
    [ ! -L "$installer_archive" ] && [ -f "$installer_archive" ] || return 1
    checksums_size=$($wc_command -c <"$checksums") || return 1
    [ "$checksums_size" -le 1048576 ] || return 1
    expected_digest=$(
        "$awk_command" -v selected="$installer_archive_name" '
            BEGIN { found = 0; valid = 1 }
            {
                if (length($0) < 67 || substr($0, 65, 2) != "  ") {
                    valid = 0
                    next
                }
                digest = substr($0, 1, 64)
                name = substr($0, 67)
                if (digest !~ /^[0-9a-f]+$/ || name !~ /^[A-Za-z0-9._-]+$/) {
                    valid = 0
                    next
                }
                if (seen[name]++) {
                    valid = 0
                    next
                }
                if (name == selected) {
                    expected = digest
                    found++
                }
            }
            END {
                if (!valid || found != 1) {
                    exit 1
                }
                print expected
            }
        ' "$checksums"
    ) || return 1
    actual_digest=$(sha256_digest "$installer_archive") || return 1
    [ "$actual_digest" = "$expected_digest" ]
}

# Verifies one native archive file size without extracting outside the private root.
verify_native_archive_file() {
    archive_member=$1
    archive_maximum_size=$2
    archive_member_output="$temporary/li_installer_archive_member"
    rm -f -- "$archive_member_output"
    "$tar_command" -xOzf "$installer_archive" "$archive_member" \
        >"$archive_member_output" 2>/dev/null || return 1
    archive_member_size=$($wc_command -c <"$archive_member_output") || return 1
    rm -f -- "$archive_member_output"
    [ "$archive_member_size" -gt 0 ] && [ "$archive_member_size" -le "$archive_maximum_size" ]
}

# Verifies native archive paths, types, modes, and size bounds before extraction.
verify_native_archive() {
    archive_expected="$temporary/li_installer_archive_expected"
    archive_members="$temporary/li_installer_archive_members"
    archive_details="$temporary/li_installer_archive_details"
    if [ "$platform_os" = "macos" ]; then
        printf '%s\n' \
            installer \
            installer/bin \
            installer/bin/li_installer \
            installer/bin/li_installer_macos_probe \
            installer/schemas \
            installer/schemas/li_installer_installation_probe_v1.schema.json \
            >"$archive_expected"
    else
        printf '%s\n' \
            installer \
            installer/bin \
            installer/bin/li_installer \
            installer/schemas \
            installer/schemas/li_installer_installation_probe_v1.schema.json \
            >"$archive_expected"
    fi
    "$tar_command" -tzf "$installer_archive" 2>/dev/null \
        | "$sed_command" 's:/$::' \
        | LC_ALL=C "$sort_command" >"$archive_members" || return 1
    LC_ALL=C "$sort_command" "$archive_expected" >"$archive_expected.sorted" || return 1
    "$cmp_command" -s "$archive_expected.sorted" "$archive_members" || return 1
    "$tar_command" -tvzf "$installer_archive" >"$archive_details" 2>/dev/null || return 1
    "$awk_command" '
        {
            name = $NF
            sub(/\/$/, "", name)
            expected[name] = $1
        }
        END {
            if (expected["installer"] != "drwxr-xr-x" ||
                expected["installer/bin"] != "drwxr-xr-x" ||
                expected["installer/schemas"] != "drwxr-xr-x" ||
                expected["installer/bin/li_installer"] != "-rwxr-xr-x" ||
                expected["installer/schemas/li_installer_installation_probe_v1.schema.json"] != "-rw-r--r--") {
                exit 1
            }
        }
    ' "$archive_details" || return 1
    if [ "$platform_os" = "macos" ]; then
        "$awk_command" '
            $NF == "installer/bin/li_installer_macos_probe" && $1 == "-rwxr-xr-x" { found++ }
            END { if (found != 1) exit 1 }
        ' "$archive_details" || return 1
        verify_native_archive_file installer/bin/li_installer_macos_probe 67108864 || return 1
    fi
    verify_native_archive_file installer/bin/li_installer 134217728 || return 1
    verify_native_archive_file \
        installer/schemas/li_installer_installation_probe_v1.schema.json 1048576
}

# Returns success only for one exact stable or release-candidate version.
valid_release_version() {
    printf '%s\n' "$1" | "$awk_command" '
        {
            value = $0
            if (value ~ /-rc\./) {
                count = split(value, parts, "-rc[.]")
                if (count != 2 || parts[2] !~ /^[0-9]+$/) exit 1
                value = parts[1]
            }
            count = split(value, components, ".")
            if (count != 3) exit 1
            for (component_index = 1; component_index <= 3; component_index++) {
                if (components[component_index] !~ /^[0-9]+$/) exit 1
            }
        }
    '
}

# Extracts the verified native installer into the private bootstrap root.
extract_native_installer() {
    verify_native_archive || fail "native installer archive inventory is invalid"
    installer_unpacked="$temporary/li_installer_unpacked"
    mkdir "$installer_unpacked"
    "$tar_command" -xzf "$installer_archive" -C "$installer_unpacked" \
        || fail "native installer archive could not be extracted"
    installer_native_root="$installer_unpacked/installer"
    installer_binary="$installer_native_root/bin/li_installer"
    installer_schema="$installer_native_root/schemas/li_installer_installation_probe_v1.schema.json"
    [ ! -L "$installer_binary" ] && [ -f "$installer_binary" ] \
        && [ -x "$installer_binary" ] \
        || fail "native installer binary is unavailable"
    [ ! -L "$installer_schema" ] && [ -f "$installer_schema" ] \
        || fail "native installer schema is unavailable"
    if [ "$platform_os" = "macos" ]; then
        installer_macos_probe="$installer_native_root/bin/li_installer_macos_probe"
        [ ! -L "$installer_macos_probe" ] && [ -f "$installer_macos_probe" ] \
            && [ -x "$installer_macos_probe" ] \
            || fail "native macOS probe is unavailable"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || fail "--version requires a value"
            version=$2
            shift 2
            ;;
        --prefix)
            [ "$#" -ge 2 ] || fail "--prefix requires a value"
            prefix=$2
            launcher_root="$prefix/bin"
            user_install=1
            shift 2
            ;;
        --user)
            [ -z "$prefix" ] || fail "--user and --prefix cannot be combined"
            prefix="$HOME/.local"
            launcher_root="$prefix/bin"
            user_install=1
            shift
            ;;
        --no-setup)
            run_setup=0
            shift
            ;;
        --no-progress)
            progress_enabled=0
            shift
            ;;
        --repair-docker-access)
            repair_docker_access=1
            shift
            ;;
        --control-address)
            [ "$#" -ge 2 ] || fail "--control-address requires a value"
            control_address=$2
            shift 2
            ;;
        --base-url)
            [ "$#" -ge 2 ] || fail "--base-url requires a value"
            base_url=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -ne 0 ] \
    || fail "run this installer as the user who will operate Let's Infer, not root"
[ -n "$HOME" ] || fail "HOME is unavailable"

installer_interactive_output=0
case "${TERM:-}" in
    ""|dumb) ;;
    *) [ -t 2 ] && installer_interactive_output=1 ;;
esac
installer_color_output=0
[ -z "${NO_COLOR+x}" ] && installer_color_output=1
display_manager_configure \
    "$installer_interactive_output" \
    "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" \
    "$installer_color_output" \
    "$progress_enabled" \
    || fail "display manager configuration is invalid"

case "$(uname -s)" in
    Linux) platform_os=linux ;;
    Darwin) platform_os=macos ;;
    *) fail "supported operating systems are Linux and macOS" ;;
esac
case "$(uname -m)" in
    arm64|aarch64) platform_arch=arm64 ;;
    x86_64|amd64) platform_arch=x86_64 ;;
    *) fail "supported architectures are x86_64 and arm64" ;;
esac
case "$platform_os/$platform_arch" in
    linux/arm64|linux/x86_64|macos/arm64) ;;
    *) fail "a native installer is unavailable for $platform_os/$platform_arch" ;;
esac
selected_platform="$platform_os-$platform_arch"
installer_archive_name="li_installer_${platform_os}_${platform_arch}.tar.gz"
core_archive_name="letsinfer-$platform_os-$platform_arch.tar.gz"

for command_name in awk cat cmp cp curl id mkdir mktemp rm sed sort ssh-keygen tar uname wc; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required bootstrap command is unavailable: $command_name"
done
awk_command=$(command -v awk)
cmp_command=$(command -v cmp)
curl_command=$(command -v curl)
id_command=$(command -v id)
openssl_command=$(command -v openssl 2>/dev/null || true)
sed_command=$(command -v sed)
sha256sum_command=$(command -v sha256sum 2>/dev/null || true)
shasum_command=$(command -v shasum 2>/dev/null || true)
sort_command=$(command -v sort)
tar_command=$(command -v tar)
ssh_keygen_command=$(command -v ssh-keygen)
wc_command=$(command -v wc)
[ -n "$sha256sum_command" ] || [ -n "$shasum_command" ] || [ -n "$openssl_command" ] \
    || fail "a SHA-256 utility is required"

if [ -n "$version" ]; then
    valid_release_version "$version" \
        || fail "version is not a release or release candidate"
fi

if [ -n "${LETSINFER_HOME:-}" ]; then
    letsinfer_home=$LETSINFER_HOME
else
    letsinfer_home="$HOME/.local/share/letsinfer"
fi
case "$letsinfer_home" in /*) ;; *) fail "LETSINFER_HOME must be absolute" ;; esac
case "$launcher_root" in /*) ;; *) fail "launcher root must be absolute" ;; esac

allow_insecure=${LETSINFER_ALLOW_INSECURE_RELEASE_URL:-}
signers_override=${LETSINFER_RELEASE_ALLOWED_SIGNERS_PATH:-}
case "$allow_insecure" in
    1) allow_insecure_value=true ;;
    *) allow_insecure_value=false ;;
esac
case "$run_setup" in 1) run_setup_value=true ;; *) run_setup_value=false ;; esac
case "$repair_docker_access" in 1) repair_value=true ;; *) repair_value=false ;; esac
case "$progress_enabled" in 1) progress_value=true ;; *) progress_value=false ;; esac
case "$user_install" in 1) user_install_value=true ;; *) user_install_value=false ;; esac

umask 077
temporary=$(mktemp -d "/tmp/letsinfer-install.XXXXXXXX") \
    || fail "cannot create temporary bootstrap root"
trap cleanup EXIT HUP INT TERM
checksums="$temporary/SHA256SUMS"
signature="$temporary/SHA256SUMS.sig"
installer_archive="$temporary/$installer_archive_name"
allowed_signers="$temporary/release-allowed-signers"
curl_protocols="=https"
[ "$allow_insecure" = "1" ] && curl_protocols="=https,http,file"

display_manager_present_progress 5 "Resolving release"
if [ -n "$base_url" ]; then
    release_base=$base_url
    download "$release_base/SHA256SUMS" "$checksums" \
        || fail "release checksums download failed"
elif [ -n "$version" ]; then
    release_base="https://github.com/$repository/releases/download/v$version"
    download "$release_base/SHA256SUMS" "$checksums" \
        || fail "release checksums download failed"
else
    version=auto
    release_base="https://github.com/$repository/releases/latest/download"
    download "$release_base/SHA256SUMS" "$checksums" \
        || fail "release checksums download failed"
fi
[ -n "$version" ] || version=auto

download "$release_base/SHA256SUMS.sig" "$signature" \
    || fail "release signature download failed"
display_manager_present_progress 15 "Verifying signed release"
if [ -n "$signers_override" ]; then
    [ -f "$signers_override" ] || fail "release allowed-signers override is unavailable"
    cp "$signers_override" "$allowed_signers"
else
    cat >"$allowed_signers" <<'LETSINFER_RELEASE_ALLOWED_SIGNERS'
letsinfer-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPl4ZwPrMfdYYPxhqcMGtpOlM0EoFCaHlMfjme8xV23
LETSINFER_RELEASE_ALLOWED_SIGNERS
fi
"$ssh_keygen_command" -Y verify -f "$allowed_signers" -I letsinfer-release \
    -n letsinfer-release -s "$signature" <"$checksums" >/dev/null 2>&1 \
    || fail "release checksum signature is invalid"

display_manager_present_progress 25 "Downloading native installer"
download "$release_base/$installer_archive_name" "$installer_archive" \
    || fail "native installer archive download failed"
verify_native_checksum || fail "native installer archive checksum is invalid"
display_manager_present_progress 40 "Preparing native installer"
extract_native_installer

exec "$installer_binary" \
    --allow-insecure "$allow_insecure_value" \
    --checksums-file "$checksums" \
    --control-address "$control_address" \
    --core-archive-name "$core_archive_name" \
    --curl-command "$curl_command" \
    --id-command "$id_command" \
    --letsinfer-home "$letsinfer_home" \
    --launcher-root "$launcher_root" \
    --progress-enabled "$progress_value" \
    --release-base "$release_base" \
    --release-allowed-signers-file "$allowed_signers" \
    --release-version "$version" \
    --repair-docker-access "$repair_value" \
    --run-setup "$run_setup_value" \
    --selected-platform "$selected_platform" \
    --tar-command "$tar_command" \
    --temporary-root "$temporary" \
    --user-install "$user_install_value"
