# Testing and pull-request gates

Let's Infer has one canonical regression command:

```bash
python3 -m tools.core_regression
```

It runs the CLI, benchmark, gateway, replica-orchestration, node, repository
contract, and portable macOS contract suites in isolated processes. It also
rejects unregistered test modules, so adding a new directory cannot silently
remove coverage from CI.

For a focused local iteration:

```bash
python3 -m tools.core_regression --list
python3 -m tools.core_regression --suite cli --suite regression
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
- Python and installer sources parse cleanly; and
- the native Watchdog builds and passes CTest on Linux.

The release workflow uses the same Python runner. A release therefore cannot
substitute a smaller test set than the one reviewed on its pull request.

Tests must use temporary directories and mocks for network, service-manager,
container, hardware, and upstream update boundaries. They must never depend on
a developer's installed models, API keys, node identity, Docker daemon, or GPU.
