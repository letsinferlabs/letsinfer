# Core tests

Run the complete regression suite from the repository root:

```bash
python3 -m tools.core_regression
```

Use `--list` to inspect the registered suites or `--suite NAME` for a focused
local run. The canonical runner executes each suite in an isolated Python
process and fails if a new `test_*.py` file is not registered. Do not use a
single recursive `unittest discover -s tests` command: several suite roots are
deliberately independent packages and that command can silently omit them.

The tests exercise Let's Infer's control-plane contracts without importing a
real model runtime. `cli/` covers runtime candidates, Engine protocol,
lifecycle, packaging, installation, mocked updates, and failure recovery;
`benchmarks/` covers engine-neutral runners; `gateway/`, `orchestration/`, and
`site/` cover request routing, replicas, node control, and telemetry.
`regression/` proves that every public and internal CLI leaf parses and passes
through the common dispatcher, and that CI cannot drift from this inventory.
The portable macOS release contracts are included as `macos-contract`.

`runtime_fixture.py` supplies one synthetic schema-v5 candidate with exact
model, Engine OCI, and target identities. `fixtures/runtime-source/` is a tiny
runtime-owned source root used to prove that runtime artifacts remain separate
from independently identified core bundles. None of these fixtures is
discoverable as a production runtime.

Model checkpoints, engine forks, kernels, target tuning, benchmark plans,
materialized prompts, and qualification evidence do not belong here.
Runtime-specific implementation and concise public results stay in runtime
repositories; materialized benchmark inputs live only in ignored evidence.

Pull requests to `main` and `release` must pass the named **Core regression
suite** check, including native Watchdog build and CTest. Release validation
invokes the same runner so local, PR, and publication coverage stay identical.
