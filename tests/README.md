# Core tests

Run the production Rust Core gate from the repository root:

```bash
python3 -m tools.li_core_audit --root core
cargo fmt --manifest-path core/Cargo.toml --all -- --check
RUSTFLAGS="-D warnings" cargo test --manifest-path core/Cargo.toml --workspace --all-targets --locked
```

Run the remaining build-time Python and portable product contracts with:

```bash
python3 -m tools.core_regression
```

Use `--list` to inspect the registered suites or `--suite NAME` for a focused
local run. The canonical runner executes each suite in an isolated Python
process and fails if a new `test_*.py` file is not registered. Do not use a
single recursive `unittest discover -s tests` command: several suite roots are
deliberately independent packages and that command can silently omit them.

Rust manager tests exercise the complete control plane without importing a
real model runtime. The Python inventory retains benchmark-tooling,
runtime-authoring, packaging, installer, source/release audit, repository, and
portable macOS contracts. Production `core/` is Rust-only; no Python
compatibility entry point remains.

`fixtures/runtime-source/` is a tiny runtime-owned source root used to prove
that runtime artifacts remain separate from independently identified Core
bundles. It is never discoverable as a production runtime.

Model checkpoints, engine forks, kernels, target tuning, benchmark plans,
materialized prompts, and qualification evidence do not belong here.
Runtime-specific implementation and concise public results stay in runtime
repositories; materialized benchmark inputs live only in ignored evidence.

Pull requests to `main` and `release` must pass the named **Core regression
suite** check, including the warnings-denied Rust `li_watchdog` tests. Release
validation invokes the same gates so local, PR, and publication coverage stay
identical.
