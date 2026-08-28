# Let's Infer native installer

The native installer owns read-only platform observation and bounded dependency
installation before Core is downloaded. Release workflows compile these
sources into platform-specific archives; end users do not need Rust or Swift.

`install.sh` remains the single public bootstrap and the only owner of
user-facing display language. Native components emit closed semantic event
identifiers and machine-readable results.

The native lifecycle is:

```text
probe -> dependency manager -> optional package transaction -> re-probe -> verify
```

Platform service readiness is observed before mutation. Linux requires a
reachable user systemd domain with `Linger=yes`; macOS requires an active
launchd GUI domain with LaunchAgent persistence.
