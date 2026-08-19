#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

repository="letsinferlabs/letsinfer"
version=""
base_url=""
prefix=""
launcher_dir="/usr/local/bin"
user_install=0
run_setup=1
progress_active=0

clear_progress() {
    if [ "$progress_active" -eq 1 ]; then
        printf '\r\033[2K' >&2
    fi
}

progress() {
    percent=$1
    message=$2
    if [ "$progress_active" -eq 1 ]; then
        printf '\r\033[2K\033[1;33mϟ\033[0m  Installing Let\047s Infer  %3s%%  %s' \
            "$percent" "$message" >&2
    fi
}

finish_progress() {
    if [ "$progress_active" -eq 1 ]; then
        progress 100 "Complete"
        printf '\n' >&2
        progress_active=0
    fi
}

usage() {
    cat <<'EOF'
Usage: install.sh [--version VERSION] [--prefix PATH] [--user] [--no-setup]

Install and initialize the latest stable Let's Infer core release. The default
is a system command in /usr/local/bin backed by immutable files in
/opt/letsinfer. --user installs under ~/.local without administrator access.
EOF
}

fail() {
    clear_progress
    printf 'letsinfer install: %s\n' "$*" >&2
    exit 1
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
            user_install=1
            shift 2
            ;;
        --user)
            [ -z "$prefix" ] || fail "--user and --prefix cannot be combined"
            prefix="$HOME/.local"
            user_install=1
            shift
            ;;
        --no-setup)
            run_setup=0
            shift
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
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[ "$(id -u)" -ne 0 ] || fail "run this installer as the user who will operate Let's Infer, not root"
[ -n "$HOME" ] || fail "HOME is unavailable"
allow_insecure=$(printenv LETSINFER_ALLOW_INSECURE_RELEASE_URL 2>/dev/null || true)
signers_override=$(printenv LETSINFER_RELEASE_ALLOWED_SIGNERS_PATH 2>/dev/null || true)
current_path=$(printenv PATH 2>/dev/null || true)
case "${TERM:-}" in
    ""|dumb) ;;
    *)
        if [ -t 2 ]; then
            progress_active=1
        fi
        ;;
esac

case "$(uname -s)" in
    Linux) platform_os="linux" ;;
    Darwin) platform_os="macos" ;;
    *) fail "supported operating systems are Linux and macOS" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) platform_arch="x86_64" ;;
    arm64|aarch64) platform_arch="arm64" ;;
    *) fail "supported architectures are x86_64 and arm64" ;;
esac
archive_name="letsinfer-$platform_os-$platform_arch.tar.gz"

for command_name in curl python3 ssh-keygen tar mktemp; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command is unavailable: $command_name"
done
if [ "$user_install" -eq 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail "sudo is required for the default system installation"
    sudo -v
    prefix="/opt/letsinfer"
fi

if [ -n "$version" ]; then
    python3 - "$version" <<'PY' || fail "version is not a release or release candidate"
import re
import sys

if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?", sys.argv[1]) is None:
    raise SystemExit(1)
PY
fi

umask 077
temporary=$(mktemp -d "/tmp/letsinfer-install.XXXXXXXX")
cleanup() {
    clear_progress
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

progress 5 "Resolving release"

checksums="$temporary/SHA256SUMS"
signature="$temporary/SHA256SUMS.sig"
archive="$temporary/$archive_name"
allowed_signers="$temporary/release-allowed-signers"

curl_protocols="=https"
if [ "$allow_insecure" = "1" ]; then
    curl_protocols="=https,http,file"
fi

download() {
    source_url=$1
    output_path=$2
    case "$source_url" in
        https://*) ;;
        http://*|file://*)
            [ "$allow_insecure" = "1" ] \
                || fail "release URL must use HTTPS"
            ;;
        *) fail "release URL is invalid" ;;
    esac
    curl --fail --location --silent --show-error \
        --proto "$curl_protocols" --tlsv1.2 \
        --output "$output_path" "$source_url"
}

if [ -n "$base_url" ]; then
    release_base=$base_url
    download "$release_base/SHA256SUMS" "$checksums"
elif [ -n "$version" ]; then
    release_base="https://github.com/$repository/releases/download/v$version"
    download "$release_base/SHA256SUMS" "$checksums"
else
    metadata="$temporary/latest.json"
    download "https://api.github.com/repos/$repository/releases/latest" "$metadata"
    version=$(python3 - "$metadata" <<'PY'
import json
import pathlib
import re
import sys

try:
    value = pathlib.Path(sys.argv[1]).read_bytes()
    if len(value) > 1024 * 1024:
        raise ValueError
    tag = json.loads(value)["tag_name"]
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(tag, str) or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) is None:
    raise SystemExit(1)
print(tag[1:])
PY
    ) || fail "latest stable release metadata is invalid"
    release_base="https://github.com/$repository/releases/download/v$version"
    download "$release_base/SHA256SUMS" "$checksums"
fi

download "$release_base/SHA256SUMS.sig" "$signature"
download "$release_base/$archive_name" "$archive"
progress 35 "Verifying signed release"

if [ -n "$signers_override" ]; then
    [ -f "$signers_override" ] \
        || fail "release allowed-signers override is unavailable"
    cp "$signers_override" "$allowed_signers"
else
    cat >"$allowed_signers" <<'LETSINFER_RELEASE_ALLOWED_SIGNERS'
letsinfer-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPl4ZwPrMfdYYPxhqcMGtpOlM0EoFCaHlMfjme8xV23
LETSINFER_RELEASE_ALLOWED_SIGNERS
fi

ssh-keygen -Y verify -f "$allowed_signers" -I letsinfer-release \
    -n letsinfer-release -s "$signature" <"$checksums" >/dev/null 2>&1 \
    || fail "release checksum signature is invalid"

python3 - "$checksums" "$archive_name" "$archive" <<'PY' \
    || fail "release archive checksum is invalid"
import hashlib
import pathlib
import re
import sys

document = pathlib.Path(sys.argv[1]).read_bytes()
name = sys.argv[2]
archive = pathlib.Path(sys.argv[3])
if len(document) > 1024 * 1024:
    raise SystemExit(1)
records = {}
for line in document.splitlines():
    match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
    if match is None:
        raise SystemExit(1)
    item = match.group(2).decode("ascii")
    if item in records:
        raise SystemExit(1)
    records[item] = match.group(1).decode("ascii")
expected = records.get(name)
if expected is None:
    raise SystemExit(1)
digest = hashlib.sha256()
with archive.open("rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
if digest.hexdigest() != expected:
    raise SystemExit(1)
PY

progress 55 "Verifying source archive"

unpacked="$temporary/unpacked"
mkdir "$unpacked"
tar -xzf "$archive" -C "$unpacked"
[ -d "$unpacked/letsinfer" ] || fail "release archive root is missing"
(cd "$unpacked/letsinfer" && python3 -m tools.source_archive verify "$archive" >/dev/null) \
    || fail "release source manifest verification failed"
if [ -z "$version" ]; then
    version=$(
        cd "$unpacked/letsinfer"
        python3 -c 'from core import PRODUCT_VERSION; print(PRODUCT_VERSION)'
    ) || fail "release version is unreadable"
fi

progress 70 "Installing core"

if [ "$run_setup" -eq 1 ]; then
    if [ "$platform_os" = "linux" ]; then
        for setup_command in docker cmake ctest cc openssl; do
            command -v "$setup_command" >/dev/null 2>&1 \
                || fail "automatic Linux setup requires: $setup_command"
        done
        command -v loginctl >/dev/null 2>&1 \
            || fail "persistent setup requires systemd-logind"
        operator=$(id -un)
        linger=$(loginctl show-user "$operator" --property Linger --value 2>/dev/null || true)
        if [ "$linger" != "yes" ]; then
            command -v sudo >/dev/null 2>&1 \
                || fail "sudo is required once to enable persistent user services"
            sudo loginctl enable-linger "$operator"
            linger=$(loginctl show-user "$operator" --property Linger --value 2>/dev/null || true)
            [ "$linger" = "yes" ] \
                || fail "persistent user services could not be enabled"
        fi
    else
        launchctl print "gui/$(id -u)" >/dev/null 2>&1 \
            || fail "automatic setup requires an active macOS login session"
    fi
fi

umask 022
if [ "$user_install" -eq 1 ]; then
    "$unpacked/letsinfer/bin/letsinfer-install" --prefix "$prefix" >/dev/null
    command_path="$prefix/bin/letsinfer"
else
    sudo "$unpacked/letsinfer/bin/letsinfer-install" --prefix "$prefix" >/dev/null
    for managed_directory in \
        "$prefix" \
        "$prefix/bin" \
        "$prefix/lib" \
        "$prefix/lib/letsinfer" \
        "$prefix/lib/letsinfer/$version"
    do
        sudo chmod 0755 "$managed_directory"
    done
    sudo install -d -m 0755 "$launcher_dir"
    for launcher_name in letsinfer letsinfer-recovery; do
        launcher="$launcher_dir/$launcher_name"
        if [ -e "$launcher" ] && [ ! -L "$launcher" ]; then
            fail "refusing to replace a non-symlink launcher: $launcher"
        fi
        temporary_launcher="$launcher.letsinfer.$$"
        sudo rm -f -- "$temporary_launcher"
        sudo ln -s "$prefix/bin/$launcher_name" "$temporary_launcher"
        sudo mv -f -- "$temporary_launcher" "$launcher"
    done
    # A prior user install can appear earlier in PATH than /usr/local/bin.
    # Repoint only launchers whose symlink target proves they were created by
    # Let's Infer's standard ~/.local layout; never replace an arbitrary file
    # or user-managed link.
    legacy_launcher_dir="$HOME/.local/bin"
    for launcher_name in letsinfer letsinfer-recovery; do
        legacy_launcher="$legacy_launcher_dir/$launcher_name"
        if [ -L "$legacy_launcher" ]; then
            legacy_target=$(readlink "$legacy_launcher")
            case "$legacy_target" in
                "$HOME"/.local/lib/letsinfer/*/bin/"$launcher_name")
                    temporary_legacy="$legacy_launcher.letsinfer.$$"
                    rm -f -- "$temporary_legacy"
                    ln -s "$launcher_dir/$launcher_name" "$temporary_legacy"
                    mv -f -- "$temporary_legacy" "$legacy_launcher"
                    ;;
            esac
        fi
    done
    command_path="$launcher_dir/letsinfer"
fi
umask 077

if [ "$run_setup" -eq 1 ]; then
    setup_log="$temporary/setup.log"
    progress 80 "Initializing services"
    if ! "$command_path" setup >"$setup_log" 2>&1; then
        clear_progress
        sed -n '1,$p' "$setup_log" >&2
        fail "site initialization failed"
    fi
fi

finish_progress

if [ "$run_setup" -eq 1 ] && [ -s "$setup_log" ]; then
    sed -n '1,240p' "$setup_log" >&2
fi

if [ "$run_setup" -eq 1 ]; then
    completion="installed and initialized"
else
    completion="installed"
fi
printf 'Let\047s Infer %s %s for %s/%s.\n' \
    "$version" "$completion" "$platform_os" "$platform_arch" >&2
if [ "$user_install" -eq 1 ]; then
    case ":$current_path:" in
        *":$prefix/bin:"*) ;;
        *) printf 'Open a new shell after adding %s/bin to PATH.\n' "$prefix" >&2 ;;
    esac
fi
