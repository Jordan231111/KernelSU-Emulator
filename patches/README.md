# Kernel patch licensing and scope

The patches in this directory are modifications to GPL-2.0-only kernel code and are distributed under **GPL-2.0-only**. Original upstream copyright notices remain applicable.

- `mumu-task-layout.patch` applies to Android common commit `f931d3c324845b1be4337d27b565351fb581f206`.
- `kernelsu-next-mumu.patch` applies to KernelSU Next legacy commit `c81cdf51c3bb606836c6fc9a7cc858053eb0bc62`.

The build uses these exact revisions, the included configuration, and zero-fuzz patch application. The result is a custom MuMu port, not an unmodified upstream KernelSU release. See [research](../research/MUMU.md) for the reason for each change.
