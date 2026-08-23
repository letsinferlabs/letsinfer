# macOS release

[Back to documentation](../README.md)

The native macOS controller has an independent release lifecycle. Core tags,
core release branches, and `PRODUCT_VERSION` do not set or publish the app's
version. The app owns these Xcode settings in `apps/macos/project.yml`:

- `MARKETING_VERSION` is the user-visible app version;
- `CURRENT_PROJECT_VERSION` is the monotonically increasing build number.

`apps/macos/release_metadata.py` requires those values to match the generated
Xcode project and the bundle's variable-backed version fields. App tags use
`macos-vVERSION-build.BUILD`, so they cannot collide with core's `vVERSION`
namespace. macOS releases are explicitly never marked as the repository's
latest release; the latest route remains reserved for the core installer.

## Validation and publication

Pull requests to `main` run macOS validation when the app, private node API,
or Watchdog wire contract changes. Pull requests to the protected
`macos-release` branch run the same app-owned contract tests and native Xcode
tests. Merging into `macos-release` repeats validation and then:

1. resolves and validates the independent app version and build;
2. refuses an existing namespaced tag;
3. imports the Developer ID certificate into a temporary keychain;
4. builds a universal `arm64`/`x86_64` Release archive;
5. verifies its bundle versions, architectures, and code signature;
6. submits it to Apple notarization and staples the accepted ticket;
7. creates provenance attestations for the ZIP and checksum;
8. publishes the namespaced GitHub release without changing `latest`; and
9. downloads and re-verifies the exact asset, checksum, attestation, code
   signature, notarization ticket, and Gatekeeper assessment.

The publish job uses the protected `production-macos-release` environment.
Configure these environment secrets before the first app promotion:

```text
LETSINFER_APPLE_APP_PASSWORD
LETSINFER_APPLE_ID
LETSINFER_APPLE_TEAM_ID
LETSINFER_MACOS_CERTIFICATE_P12_B64
LETSINFER_MACOS_CERTIFICATE_PASSWORD
```

The certificate must contain the Developer ID Application identity for the
configured team. The workflow writes it only to the runner's temporary
directory, imports it into an ephemeral keychain, and removes both before the
job ends. Apple code signing and notarization authenticate the application;
GitHub provenance binds the exact published container and checksum to the
release workflow.

To publish, bump the app-owned version and/or build on `main`, then merge a PR
from `main` into `macos-release`. A core-only change does not bump, tag, build,
or publish the app.
