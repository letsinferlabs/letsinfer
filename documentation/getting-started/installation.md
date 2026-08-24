# Install Let's Infer

[Back to documentation](../README.md)

## Install core

On Linux or macOS:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh
```

The installer detects your OS and architecture, downloads the signed release,
verifies its checksum and complete source manifest, installs immutable core
files below `$LETSINFER_HOME/core`, exposes `letsinfer` in
`/usr/local/bin`, and runs `letsinfer setup`.

On Linux, setup checks for its compiler, CMake, and OpenSSL requirements and
uses the system package manager to install any that are missing before services
are initialized.

Run the installer as the account that will operate Let's Infer, not as root.
The default install asks for sudo only to create the launcher. It does not put
runtime data or secrets in a system directory.

For an install without administrator access:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh -s -- --user
```

This exposes the command from `~/.local/bin`. Add that directory to `PATH` if
your shell does not already include it.

Useful installer options:

```text
--version VERSION
--user
--prefix ABSOLUTE_PATH
--no-setup
--no-progress
```

Use `--no-setup` only when you want to install files without initializing a
node.

## Choose the data directory

By default, all Let's Infer data lives in:

```text
~/.local/share/letsinfer
```

Set an absolute path before installation if you want another location:

```bash
export LETSINFER_HOME=/data/letsinfer
curl -fsSL https://letsinfer.ai/install.sh | sh
```

Keep the same value in future shells and services. The directory must be owned
by your account and cannot be a symlink, `/`, or your home directory itself.

## Install a model

After setup:

```bash
letsinfer install qwen3.8-27b
```

You only provide the model name. Let's Infer detects your hardware,
chooses the best qualified runtime from the signed catalog, downloads its exact
model revision and Engine OCI, verifies them, and starts the service.

## What happens automatically

A normal model install is complete only when the local API is ready:

1. the signed catalog is verified;
2. your hardware is matched to the best qualified runtime;
3. exact model artifacts, the runtime pack, and Engine OCI are acquired and
   deduplicated;
4. persistent node, gateway, Watchdog, recovery, and engine services are
   installed;
5. the model starts; and
6. the command waits for the OpenAI-compatible endpoint to become ready.

On Linux, the selected runtime starts again after reboot. The recovery
controller also handles ordinary engine failures. A protection or OOM trip is
different: it stays latched so an automatic restart cannot hide the cause. Run
`letsinfer status` or `letsinfer doctor`, then use `letsinfer recover` when it
is safe to continue.

For a staged install that should not start inference yet:

```bash
letsinfer install qwen3.8-27b --no-start
```

To install one exact candidate:

```bash
letsinfer install qwen3.8-27b \
  --runtime sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark
```

## Check your service

```bash
letsinfer status
letsinfer doctor
letsinfer key create my-app
```

Your main node advertises its LAN endpoint with mDNS:

```text
http://<hostname>.local:8000/v1
```

Use the API key returned by `letsinfer key create my-app` as a bearer token. Key
material is shown once.

## Updates

```bash
letsinfer update check
letsinfer update
letsinfer upgrade qwen3.8-27b
```

Core and runtime updates are independent. Updating core does not change your
runtime or models. Upgrading a runtime does not change core.

## Remove Let's Infer

```bash
letsinfer uninstall
```

The command shows what it will remove and asks for confirmation. To preserve
downloaded models:

```bash
letsinfer uninstall --keep-models
```
