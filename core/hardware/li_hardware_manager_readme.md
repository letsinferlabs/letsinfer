# HardwareManager

`li_hardware_manager` owns refreshable, boot-scoped hardware observations.
Platform and device providers return CPU, memory, accelerator, telemetry, and
interconnect facts; they never decide runtime compatibility or placement.

The manager assigns observation identity and time, validates provider output
through `li_core_interface`, retains the latest snapshot, and distinguishes
first observation, semantic change, and ordinary refresh. Linux parses procfs,
fixed NVIDIA driver/CUDA labels, telemetry/topology, and RDMA output. macOS
parses fixed sysctl facts and the core-owned Swift/Metal helper. Every native
dependency is injected and the same parsers run against deterministic CI
fixtures.

`li_hardware_observation` schema 1 is the one strict HardwareManager document
boundary. Node persistence stores that exact raw document and decodes it only
through HardwareManager, so duplicate, unknown, future, corrupt, or unbounded
state fails closed after restart. Mutable links remain scoped to the exact
boot identity, observation identity, and observation time; callers classify
freshness against an explicit maximum age.

Production native reads accept only normalized, no-follow, singly-linked,
owner-trusted regular files with safe modes and bounded UTF-8 output. Native
commands run shell-free in their own process group with a bounded injected
wait policy; timeout or incomplete inherited output terminates the group.
