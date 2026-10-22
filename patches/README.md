# Kernel patches

These patches modify GPL-2.0-only kernel code and are distributed under **GPL-2.0-only**. Upstream copyright notices remain applicable.

| Patch | Target | Purpose |
| --- | --- | --- |
| `mumu-task-layout.patch` | Android common `f931d3c324845b1be4337d27b565351fb581f206` | Match MuMu's measured task layout |
| `kernelsu-next-mumu.patch` | KernelSU Next legacy `c81cdf51c3bb606836c6fc9a7cc858053eb0bc62` | Adapt root hooks, credentials, and loading to MuMu |
| `susfs-lkm-mumu.patch` | SUSFS LKM legacy `0b197bfd3d3402ee108e19c66ed3293d9d14481a` | Adapt filesystem hooks and locking to MuMu's kernel |

The build uses these exact revisions, the profile's configuration, and zero-fuzz patch application. SUSFS files listed in its profile are normalized to LF before patching. Recheck ABI assumptions before applying the patches to another kernel.
