#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

repository="letsinferlabs/letsinfer"
version=""
prefix="${HOME}/.local"
base_url=""

usage() {
    cat <<'EOF'
Usage: install.sh [--version VERSION] [--prefix PATH]

Install the latest stable Let's Infer core release. A version selects the
immutable vVERSION GitHub release instead. The default prefix is ~/.local.
EOF
}

fail() {
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
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[ "$(uname -s)" = "Linux" ] || fail "core installation currently requires Linux"
for command_name in curl openssl python3 sha256sum tar mktemp; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
if [ -n "$version" ]; then
    python3 - "$version" <<'PY' || fail "version is not a release or release candidate"
import re
import sys

if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?", sys.argv[1]) is None:
    raise SystemExit(1)
PY
fi

umask 077
temporary=$(mktemp -d "${TMPDIR:-/tmp}/letsinfer-install.XXXXXXXX")
cleanup() {
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

checksums="$temporary/SHA256SUMS"
signature="$temporary/SHA256SUMS.sig"
archive="$temporary/letsinfer.tar.gz"
public_key="$temporary/release-public-key.pem"

curl_protocols="=https"
if [ "${LETSINFER_ALLOW_INSECURE_RELEASE_URL:-0}" = "1" ]; then
    curl_protocols="=https,http,file"
fi

download() {
    source_url=$1
    output_path=$2
    case "$source_url" in
        https://*) ;;
        http://*|file://*)
            [ "${LETSINFER_ALLOW_INSECURE_RELEASE_URL:-0}" = "1" ] || fail "release URL must use HTTPS"
            ;;
        *) fail "release URL is invalid" ;;
    esac
    curl --fail --location --silent --show-error \
        --proto "$curl_protocols" --tlsv1.2 \
        --output "$output_path" "$source_url"
}

if [ -n "$base_url" ]; then
    release_base=${base_url%/}
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
download "$release_base/letsinfer.tar.gz" "$archive"

if [ -n "${LETSINFER_RELEASE_PUBLIC_KEY_PATH:-}" ]; then
    [ -f "$LETSINFER_RELEASE_PUBLIC_KEY_PATH" ] || fail "release public key override is unavailable"
    cp "$LETSINFER_RELEASE_PUBLIC_KEY_PATH" "$public_key"
else
    cat >"$public_key" <<'LETSINFER_RELEASE_PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAk+XhnA+sx91hg/GGpwwa2k6UzQSgUJoeUx+OZ7zFXbc=
-----END PUBLIC KEY-----
LETSINFER_RELEASE_PUBLIC_KEY
fi

openssl pkeyutl -verify -pubin -inkey "$public_key" -rawin \
    -in "$checksums" -sigfile "$signature" >/dev/null 2>&1 \
    || fail "release checksum signature is invalid"

python3 - "$checksums" <<'PY' || fail "release checksum document is invalid"
import pathlib
import re
import sys

value = pathlib.Path(sys.argv[1]).read_bytes()
if re.fullmatch(rb"[0-9a-f]{64}  letsinfer\.tar\.gz\n", value) is None:
    raise SystemExit(1)
PY

(cd "$temporary" && sha256sum --check --strict SHA256SUMS >/dev/null) \
    || fail "release archive checksum is invalid"

unpacked="$temporary/unpacked"
mkdir "$unpacked"
tar -xzf "$archive" -C "$unpacked"
[ -d "$unpacked/letsinfer" ] || fail "release archive root is missing"
(cd "$unpacked/letsinfer" && python3 -m tools.source_archive verify "$archive" >/dev/null) \
    || fail "release source manifest verification failed"
"$unpacked/letsinfer/bin/letsinfer-install" --prefix "$prefix"

printf 'Let\047s Infer installed. Add %s/bin to PATH if needed.\n' "$prefix" >&2
