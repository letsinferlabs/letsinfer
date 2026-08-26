#!/bin/sh
set -eu

VERSION="b10621"
EXPECTED_SHA256="ea50671b3dfe86136be16448763f94642c53443df96964777b4e1c3d51f06e20"
URL="https://github.com/ggml-org/llama.cpp/releases/download/${VERSION}/llama-${VERSION}-xcframework.zip"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
VENDOR_DIR="$PROJECT_DIR/Vendor"
ARCHIVE="$VENDOR_DIR/llama-${VERSION}-xcframework.zip"
STAGING="$VENDOR_DIR/.llama-${VERSION}-staging"

mkdir -p "$VENDOR_DIR"
curl --fail --location --proto '=https' --tlsv1.2 --output "$ARCHIVE" "$URL"
ACTUAL_SHA256=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "llama.cpp XCFramework checksum mismatch" >&2
  exit 1
fi

rm -rf "$STAGING"
mkdir "$STAGING"
unzip -q "$ARCHIVE" -d "$STAGING"
FRAMEWORK=$(find "$STAGING" -type d -name 'llama.xcframework' -maxdepth 4 -print -quit)
if [ -z "$FRAMEWORK" ]; then
  echo "llama.xcframework is missing from the verified archive" >&2
  exit 1
fi
rm -rf "$VENDOR_DIR/llama.xcframework"
mv "$FRAMEWORK" "$VENDOR_DIR/llama.xcframework"
rm -rf "$STAGING"

echo "Installed llama.cpp ${VERSION} (${EXPECTED_SHA256})"
