# Core tests

These tests exercise Let's Infer's control-plane contracts without importing a
real model runtime. `cli/` covers runtime candidates, the Engine protocol,
lifecycle, packaging,
and installation; `benchmarks/` covers the engine-neutral runners.

`runtime_fixture.py` supplies one synthetic schema-v3 candidate with exact
model, Engine OCI, and target identities. `fixtures/runtime-source/` is a tiny
runtime-owned source root used to prove that runtime artifacts remain separate
from independently identified core bundles. None of these fixtures is
discoverable as a production runtime.

Model checkpoints, engine forks, kernels, target tuning, benchmark plans,
materialized prompts, and qualification evidence do not belong here.
Runtime-specific implementation and concise public results stay in runtime
repositories; materialized benchmark inputs live only in ignored evidence.
