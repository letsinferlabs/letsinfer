# Let's Infer for iOS

This is the native iPhone/iPad Let's Infer node. It implements the code-less
`letsinfer node add` LAN flow and can host a placement group while the app is
active. The default build embeds llama.cpp; the optional MLC build embeds MLC
LLM's Metal runtime and a compiled model library. Metal is the accelerator
backend, not a separate Engine.

## What works

- persistent P-256 physical-machine identity in the iOS Keychain;
- generated TLS 1.3 node identity with certificate-pinned discovery;
- `_letsinfer._tcp` Bonjour advertisement on port 9770;
- exact `letsinfer-node-add-v1` request, Accept/Deny, challenge, proof, and LAN
  enrollment against the selected main node;
- authenticated child facts published every five seconds as `ios/arm64`, one
  Apple GPU, and unified memory;
- exact Qwen3 0.6B Q8_0 acquisition, size check, and SHA-256 verification;
- llama.cpp `b10621` compiled for iOS with Metal;
- optional MLC LLM at its exact source revision, with a complete pinned
  18-file Qwen3 MLC snapshot;
- authenticated HTTPS Engine API on port 18000 with `/health`, `/v1/models`,
  `/v1/chat/completions`, `/v1/letsinfer/token-count`, and
  `/v1/letsinfer/telemetry`;
- thermal, low-battery, Low Power Mode, and app-lifecycle admission gates;
- placement-group `stage`, `start`, `recover`, `stop`, `remove`, and status jobs
  for the two exact embedded runtime candidates;
- one last signed offline fact before background suspension when iOS grants
  the normal transition window;
- screen wake lock while serving, Guided Access UI, and a supervised
  Autonomous Single App Mode request; and
- a private-website-derived interface: exact black dark canvas, system type,
  borderless rounded activity surfaces, and the canonical eight-color palette.

The app never attempts to run a Linux Engine OCI. Runtime schema 6 carries an
explicit `embedded-application` distribution, and placement-job protocol 1 sends a
bounded native execution projection to the enrolled app over its existing mTLS
control channel. Stage fails closed unless the matching embedded Engine and
exact model are already loaded on the device.

## Immutable inputs

| Input | Identity |
| --- | --- |
| llama.cpp | release `b10621`, commit `c1d0e7a004015f23bc0233470b747b596f29b264` |
| iOS XCFramework | SHA-256 `ea50671b3dfe86136be16448763f94642c53443df96964777b4e1c3d51f06e20` |
| Model | `Qwen/Qwen3-0.6B-GGUF` |
| Revision | `23749fefcc72300e3a2ad315e1317431b06b590a` |
| File | `Qwen3-0.6B-Q8_0.gguf`, 639,446,688 bytes |
| Model SHA-256 | `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031` |

The optional MLC lane pins MLC LLM commit
`9fa644f54b04983adea4d0168f49fc6af4a893ba` and
`mlc-ai/Qwen3-0.6B-q4f16_1-MLC` revision
`8c14ce481d4c692769976ad52afea453a102df19`. The snapshot is 351,517,143
bytes across 18 files; every LFS object is verified before the model loads.

The model is downloaded as data after installation; no executable code is
downloaded. Model files are excluded from device backups and retained across
normal app launches.

## Build

Requirements: Xcode 26, XcodeGen, and an iOS 17-or-newer physical arm64
device. Device signing is deployment-owned: choose a team in your local Xcode
project or CI secret. No signing-team identity belongs in this repository or
in an Engine payload.

```bash
cd apps/ios
./scripts/fetch-llama.sh
xcodegen generate --spec project.yml
open LetsInferIOS.xcodeproj
```

Choose your development team for the `LetsInferIOS` target, connect the device,
and Run. The official release XCFramework contains an iOS device slice but no
iOS Simulator slice, so inference builds target physical devices.

To reproduce the non-signing build and compile the tests:

```bash
xcodebuild \
  -project LetsInferIOS.xcodeproj \
  -scheme LetsInferIOS \
  -configuration Debug \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  build-for-testing
```

For the optional MLC build, prepare a recursive checkout at the exact commit
above with the MLC-documented CMake, Rust, Python, and TVM prerequisites. Then:

```bash
./scripts/prepare-mlc.sh \
  /path/to/runtimes/mlc--mlc-ai--qwen3-0.6b-q4f16_1-mlc--ios-apple-gpu \
  /path/to/mlc-llm \
  /path/to/Qwen3-0.6B-q4f16_1-MLC
xcodegen generate --spec project.mlc.yml
```

The preparation script refuses a different MLC commit and checks the complete
static-library output before replacing ignored local vendor inputs. Generated
libraries, model code, weights, and Xcode projects remain outside Git.

## Use

1. Open the app and allow Local Network access.
2. Download and load one pinned model lane.
3. Keep the app active. For a dedicated device, enable Guided Access with the
   side-button shortcut or install an MDM Single App Mode profile.
4. On the current standalone main node, run `letsinfer node add`.
5. Select the iPhone/iPad and tap **Accept** in the app.

The main records an active child and receives signed facts. Installing either
unqualified iOS runtime candidate can then create its one-placement group on
the device after the matching model is loaded. The direct Engine endpoint is
also available at `https://<device-address>:18000`; use the displayed
certificate SHA-256 and bearer key rather than disabling TLS verification.

## Availability semantics

iOS normally suspends applications in the background. The app does not claim an
unrelated background entitlement: leaving the foreground stops its listeners
and inference admission, and the main falls back to fact staleness if the final
offline publication cannot complete. Guided Access and Single App Mode keep the
app foregrounded, which is the supported inference deployment mode.

Inference pauses at serious/critical thermal state, in Low Power Mode, or below
15% battery while unplugged. `/health` becomes unavailable during those states;
the placement group becomes unavailable rather than being silently moved to another
runtime. The model and verified download remain on disk for explicit recovery.

## Security boundary

The standalone node-add listener accepts only bounded JSON over TLS 1.3. After
enrollment it restarts with the main node's CA and exact coordinator member ID
required at the TLS handshake. The Engine endpoint uses a separate Keychain
bearer key and the node's pinned certificate. Prompts and responses are not
persisted by the app.

See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for upstream licensing.
