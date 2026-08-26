#!/bin/sh
set -eu

candidate=${1:?usage: prepare-mlc.sh CANDIDATE_DIRECTORY MLC_LLM_SOURCE_DIRECTORY MLC_MODEL_SOURCE_DIRECTORY}
source_root=${2:?usage: prepare-mlc.sh CANDIDATE_DIRECTORY MLC_LLM_SOURCE_DIRECTORY MLC_MODEL_SOURCE_DIRECTORY}
model_root=${3:?usage: prepare-mlc.sh CANDIDATE_DIRECTORY MLC_LLM_SOURCE_DIRECTORY MLC_MODEL_SOURCE_DIRECTORY}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname "$script_dir")
vendor="$project_dir/Vendor"
staging="$vendor/.mlc-staging"

mkdir -p "$vendor"
rm -rf "$staging"
mkdir -p "$staging"
MLC_LLM_SOURCE_DIR="$source_root" \
MLC_MODEL_SOURCE_DIR="$model_root" \
  "$candidate/scripts/build-ios-engine.sh" "$staging"

rm -rf "$vendor/MLCSwift" "$vendor/MLC"
cp -R "$source_root/ios/MLCSwift" "$vendor/MLCSwift"
mkdir -p "$vendor/MLC"
mv "$staging/dist/lib" "$vendor/MLC/lib"
mv "$staging/dist/bundle" "$vendor/MLC/bundle"
rm -rf "$staging"

echo "Prepared pinned MLC iOS libraries; generate with project.mlc.yml"
