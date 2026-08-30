# Benchmark schemas

The `li_benchmark_` files are the centralized structural schemas for the
current public benchmark boundary:

- contract schema 8;
- OCI execution-payload record schema 7;
- native execution-payload record schema 8;
- paired community-verification record schema 1;
- one workload-result shape; and
- one compact telemetry-timeline shape.

The filenames use the Let's Infer namespace. Existing published documents keep
their established `schema_version` fields and values; changing their wire shape
would require a separately reviewed public schema version.

JSON Schema owns types, closed field sets, constants, ranges, patterns, and
nesting. Core's semantic validators continue to own canonical hashes, record
identity, timestamp derivation, ordered uniqueness, workload/concurrency
cardinality, telemetry maxima, TTFT arithmetic, and cross-document binding.
`tests/benchmarks/test_benchmark_schemas.py` requires both layers to agree and
runs automatically in the canonical Core regression suite.
