# Testing and pull-request gates

The native Rust workspace is the production Core gate. The `core/` tree is
Rust-only; Python under `benchmarks/` and `tools/` is build-time or diagnostic
tooling, never a product entry point or compatibility runtime.

```bash
python3 -m tools.li_core_audit --root core
cargo fmt --manifest-path core/Cargo.toml --all -- --check
RUSTFLAGS="-D warnings" cargo test --manifest-path core/Cargo.toml --workspace --all-targets --locked
```

The remaining build-time Python, benchmark-tooling, repository, and portable
macOS contracts run through:

```bash
python3 -m tools.core_regression
```

It rejects unregistered Python test modules so tooling coverage cannot silently
leave CI. Production manager, API, daemon, lifecycle, and native-provider
coverage belongs to the Rust workspace and its deterministic injected mocks.

For a focused local iteration:

```bash
python3 -m tools.core_regression --list
python3 -m tools.core_regression --suite tooling --suite regression
```

## What every core pull request proves

The required **Core regression suite** check runs on pull requests to `main`
and `release`. It verifies:

- every public and internal CLI leaf has an explicit scope and a parseable,
  mocked dispatch path;
- update availability, application, failure, rollback, and concurrent polling
  paths remain deterministic without contacting production services;
- model installation, runtime selection, lifecycle, protection, gateway,
  node, replica, benchmark, audit, and publication contracts pass;
- build-time Python, installer, and shell sources parse cleanly; and
- the Rust `li_watchdog` resident and every other workspace target compile and
  pass with warnings denied on Linux and macOS.

The release workflow runs the same Rust and surviving Python gates. A release
therefore cannot substitute a smaller test set than the one reviewed on its
pull request.

Tests must use temporary directories and mocks for network, service-manager,
container, hardware, and upstream update boundaries. They must never depend on
a developer's installed models, API keys, node identity, Docker daemon, or GPU.
