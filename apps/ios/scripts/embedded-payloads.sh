#!/bin/sh
set -eu

runtimes_root=${1:?usage: embedded-payloads.sh RUNTIMES_ROOT}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
app_root=$(dirname "$script_dir")
source_root="$app_root/LetsInferIOS"
mlc_candidate="$runtimes_root/mlc--mlc-ai--qwen3-0.6b-q4f16_1-mlc--ios-apple-gpu"

hash_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

hash_identities() {
  sed -E 's/sha256:[0-9a-f]{64}/sha256:<payload>/g' \
    "$source_root/Inference/EmbeddedEngineIdentities.swift" \
    | shasum -a 256 | awk '{print $1}'
}

llama_payload=$(
  {
    printf '%s\n' \
      letsinfer-embedded-engine-v2 \
      llamacpp \
      c1d0e7a004015f23bc0233470b747b596f29b264 \
      ea50671b3dfe86136be16448763f94642c53443df96964777b4e1c3d51f06e20 \
      ai.letsinfer.ios \
      deployment-managed
    hash_identities
    for path in \
      "$app_root/project.yml" \
      "$source_root/Inference/LlamaEngine.swift" \
      "$source_root/Inference/ModelStore.swift" \
      "$source_root/Inference/InferenceService.swift" \
      "$source_root/Inference/InferenceHTTPServer.swift" \
      "$source_root/Inference/EngineAccessKeyStore.swift" \
      "$source_root/Inference/EmbeddedGroupManager.swift" \
      "$source_root/Node/NodeHTTPServer.swift"
    do
      hash_file "$path"
    done
  } | shasum -a 256 | awk '{print $1}'
)

mlc_payload=$(
  {
    printf '%s\n' \
      letsinfer-embedded-engine-v2 \
      mlc-metal \
      9fa644f54b04983adea4d0168f49fc6af4a893ba \
      ai.letsinfer.ios \
      deployment-managed
    hash_identities
    for path in \
      "$app_root/project.yml" \
      "$app_root/project.mlc.yml" \
      "$source_root/Inference/MLCMetalEngine.swift" \
      "$source_root/Inference/MLCModelStore.swift" \
      "$source_root/Inference/InferenceService.swift" \
      "$source_root/Inference/InferenceHTTPServer.swift" \
      "$source_root/Inference/EngineAccessKeyStore.swift" \
      "$source_root/Inference/EmbeddedGroupManager.swift" \
      "$source_root/Node/NodeHTTPServer.swift" \
      "$mlc_candidate/engine/mlc-package-config.json" \
      "$mlc_candidate/engine/model-files.sha256" \
      "$mlc_candidate/scripts/build-ios-engine.sh"
    do
      hash_file "$path"
    done
  } | shasum -a 256 | awk '{print $1}'
)

printf 'llamacpp sha256:%s\nmlc-metal sha256:%s\n' \
  "$llama_payload" "$mlc_payload"
