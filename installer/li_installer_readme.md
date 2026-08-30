# Let's Infer native installer

The native installer owns the complete lifecycle after the verified shell
bootstrap: platform observation, dependency installation, Core download and
verification, immutable source activation, launchers, and Core setup. Core
setup exclusively owns the platform-service activation, stable readiness, and
commit transaction. Release workflows compile these sources into
platform-specific archives; end users do not need Rust or Swift.

`install.sh` remains the single public bootstrap. It selects and verifies one
native archive, extracts it privately, and replaces itself with
`li_installer`. Rust owns all presentation after `exec`; the shell never
resumes.

The native lifecycle is:

```text
probe -> dependency manager -> optional package transaction -> re-probe ->
Core download -> immutable install -> li_core_setup (service activation, readiness, commit)
```

Platform service-manager readiness is observed before mutation. Linux requires
a reachable user systemd domain with `Linger=yes`; macOS requires an active
launchd GUI domain with LaunchAgent persistence.
