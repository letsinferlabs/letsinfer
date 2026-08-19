# Installation

[Back to documentation](../README.md)

NVIDIA DGX Spark is the first implemented qualification target. It requires Docker, user
systemd, CMake, a C17 compiler, and OpenSSL 3 development headers. Boot
persistence requires user lingering:

```bash
sudo loginctl enable-linger "$USER"
```

Install the latest stable CLI from its signed GitHub release:

```bash
curl -fsSL https://github.com/letsinferlabs/letsinfer/releases/latest/download/install.sh | sh
```

The bootstrap verifies the Ed25519-signed checksum, archive SHA-256, and
embedded source manifest before running any repository code. It copies the
exact public source closure into a read-only version-and-hash directory and
atomically creates `~/.local/bin/letsinfer`; it does not create, restart, or
modify a site. To install from an unpacked verified source tree instead:

```bash
bin/letsinfer-install
~/.local/bin/letsinfer --help
```

Add `~/.local/bin` to `PATH` if it is not already present. Re-running the
installer verifies and reuses the same immutable source identity. It refuses
to replace a user-created regular file at either launcher path.

Create the first logical site before installing a runtime:

```bash
letsinfer setup --name Home
letsinfer site status
```

The first setup creates the coordinator, site identity, local controller,
private TLS material, default local inference key, resident Watchdog, site
service, and unified gateway. A later machine joins as a member rather than
creating a second authority. The Mac app provides the normal **Add to Home**
flow for a pristine Spark on direct ConnectX and the setup-code flow for LAN or
remote machines. See [Sites, members, and trust](../concepts/sites.md).

The coordinator advertises its inference endpoint over mDNS. On the local
network, standard OpenAI clients use `http://<hostname>.local:8000/v1` and a
site API key; they do not install a certificate. Private control and engine
connections remain TLS-protected.

Install a qualified model runtime from the built-in signed production catalog:

```bash
letsinfer install deepseek-v4-flash
```

The default catalog is fetched over HTTPS from `letsinferlabs/catalog` and
verified with the public key shipped in core. A custom remote catalog can
override that trust root at `~/.config/letsinfer/catalog-public-key.pem` or
with `LETSINFER_CATALOG_PUBLIC_KEY`. The publisher must place the exact-byte
signature document at `<catalog-url>.sig`; Let's Infer verifies the signature,
catalog SHA-256, and trust-key fingerprint before target selection. An
explicitly selected unsigned local catalog is a development input only.

Install a runtime repository during development:

```bash
letsinfer install ./my-runtime
```

Install a published OCI artifact by immutable digest:

```bash
letsinfer install \
  ghcr.io/example/example-model-runtime@sha256:0123456789abcdef...
```

Installation automatically resolves missing dependencies for qualified and
candidate runtimes. Exact model revisions use the shared Hugging Face cache, runtime
objects and native integration artifacts use Let's Infer's content-addressed
stores, and OCI image layers use Docker's content store. Existing content
under the same immutable identity is verified and reused without rebuilding.
Engine packages remain inside the runtime image. Use
`--no-download` only when the exact model and registry image content must
already be available locally.

The container runtime home is image-scoped by default. Installing or upgrading
to a different immutable image creates and mounts that image's own runtime
cache directory; Let's Infer preserves the predecessor directory but never mounts
it implicitly. Pass `--runtime-cache-root` only when deliberately selecting an
explicit compatible location.

Every managed container is also labeled with the exact release-manifest
SHA-256 and installed runtime-object digest. Boot recovery may restart an
existing stopped container only when both identities still match the active
service configuration. A missing or different identity fails closed, so an
upgrade cannot adopt a predecessor container or its integration mount.

OCI installation requires the `oras` CLI. Mutable tags are rejected. A local
directory is explicit developer input; production installations should come
from a trusted catalog or an exact OCI digest.
Let's Infer core contains no built-in model releases.

An unqualified candidate can be imported with all exact dependencies, but
Let's Infer will not make it the boot service or launch it. The import creates
private local API/TLS material so the explicit qualification command works on
a clean host. Test it explicitly and preserve evidence:

```bash
letsinfer serve example-model \
  --engine vllm \
  --qualification-mode \
  --evidence-dir ~/.cache/letsinfer/results/my-candidate
```

Normal installation verifies the exact model, image, integration artifacts,
selected site topology, memory envelope, API credentials, TLS material, and Watchdog
binary before transactionally replacing the service. Activation failure
restores the previous configuration, units, immutable bundle, and service.
