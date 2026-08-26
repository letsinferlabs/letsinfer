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
`/usr/local/bin`, and initializes the node through a private installer action.

On Linux, setup checks for its compiler, CMake, and OpenSSL requirements and
uses the system package manager to install any that are missing before services
are initialized.

Run the installer as the account that will operate Let's Infer, not as root.
The default install asks for sudo to create the launcher and enable persistent
user services. It does not put runtime data or secrets in a system directory.

The Linux installer checks the Docker CLI, daemon, and operator access before
downloading Let's Infer. If Docker is absent, it explicitly invokes `sudo` and
uses the distribution package manager: `docker.io` through apt on Ubuntu or
Debian, `moby-engine` through dnf on Fedora, or `docker` through zypper on
openSUSE/SLES and pacman on Arch/Manjaro. It then enables `docker.service` and
verifies the installed CLI and daemon. Unsupported distributions stop with an
error instead of guessing at packages or running a downloaded convenience
installer; macOS installation never changes Docker.

Before initialization, the installer also verifies Docker from a transient
systemd user service. If Docker is healthy but the operator cannot access
`/var/run/docker.sock`, the installer can add that account to the socket's
group after warning that Docker group membership is root-equivalent. Linux
requires a fresh login before the new group reaches the shell, so sign in again
and rerun the installer. If an already-running user service manager still has
stale groups, the rerun offers to restart it before initialization continues.

For an install without administrator access:

```bash
curl -fsSL https://letsinfer.ai/install.sh | sh -s -- --user
```

This exposes the command from `~/.local/bin`. Add that directory to `PATH` if
your shell does not already include it. The `--user` option does not make
system dependencies rootless: if Docker is absent, automatic setup still needs
`sudo`; use `--no-setup` to install only the Let's Infer files.

Useful installer options:

```text
--version VERSION
--user
--prefix ABSOLUTE_PATH
--no-setup
--no-progress
--repair-docker-access
```

Use `--no-setup` only when you want to install files without initializing a
node. `--repair-docker-access` explicitly approves the otherwise interactive
Docker group or user-service-manager repair, which is useful for unattended
installation.

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

After installation:

```bash
letsinfer model install qwen3.8-27b
```

You only provide the model name. Let's Infer detects your hardware,
chooses the best qualified runtime from the signed catalog, downloads its exact
model revision and Engine distribution, verifies them, and starts the service.
The Apple candidates added with runtime schema 6 remain unqualified source
candidates until physical Apple hardware evidence is accepted, so they are not
selected by the production catalog yet.

## What happens automatically

A normal model install is complete only when the local API is ready:

1. the signed catalog is verified;
2. your hardware is matched to the best qualified runtime;
3. exact model artifacts, the runtime pack, and Engine distribution are acquired and
   deduplicated;
4. persistent node, gateway, recovery, and engine services are installed;
   Linux also installs the independent Watchdog;
5. the model starts; and
6. the command waits for the OpenAI-compatible endpoint to become ready.

On Linux, the selected runtime starts again after reboot. The recovery
controller also handles ordinary engine failures. A protection or OOM trip is
different: it stays latched so an automatic restart cannot hide the cause. Run
`letsinfer status` or `letsinfer doctor`, then use `letsinfer model recover MODEL` when it
is safe to continue.

On Apple Silicon macOS, a native runtime stages its exact archive or standalone
Python payload below the Let's Infer data root and runs the adapter plus
loopback backend as a launchd user agent. The Linux Watchdog is not transferred
to macOS; native candidates must qualify their macOS memory-pressure and crash
behavior independently.

An iPhone or iPad joins through the separate native app. Keep it foregrounded
with Guided Access or supervised Single App Mode, load the matching exact model
in the app, and then use `letsinfer node add` from the main node. iOS reports
offline when suspended and never claims a general background-service
entitlement.

To install one exact candidate:

```bash
letsinfer model install qwen3.8-27b \
  --runtime sglang--radixark--qwen3.8-27b-nvfp4--dgx-spark
```

## Check your service

```bash
letsinfer status
letsinfer doctor
letsinfer auth key create my-app
```

Your main node advertises its LAN endpoint with mDNS:

```text
http://<hostname>.local:8000/v1
```

Use the API key returned by `letsinfer auth key create my-app` as a bearer token. Key
material is shown once.

## Updates

```bash
letsinfer update check
letsinfer update core
letsinfer update model qwen3.8-27b
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
