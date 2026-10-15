# Third-party components

This repository's original Python, shell, and verification code is MIT-licensed. Kernel patches are GPL-2.0-only.

The build downloads and modifies these components:

| Component | Pinned source | License |
| --- | --- | --- |
| Android common kernel headers/build infrastructure | [f931d3c](https://github.com/aosp-mirror/kernel_common/tree/f931d3c324845b1be4337d27b565351fb581f206) | Linux kernel GPL-2.0 with upstream file-level exceptions |
| KernelSU Next kernel implementation | [c81cdf5, legacy branch](https://github.com/KernelSU-Next/KernelSU-Next/tree/c81cdf51c3bb606836c6fc9a7cc858053eb0bc62) | GPL-2.0-only |
| KernelSU Next Manager and ksud | [v3.4.2](https://github.com/KernelSU-Next/KernelSU-Next/tree/v3.4.2) | GPL-3.0-or-later and upstream component licenses |

The upstream KernelSU project by weishu and KernelSU Next contributors provide the root implementation. This repository supplies the measured MuMu ABI adaptations, orchestration, and validation. It is not affiliated with NetEase or either upstream project.

MuMu's `Image`, proprietary driver binaries, APKs, and VM disks are not checked into this repository. The configuration records observed kernel build options; it contains no emulator account or device identity data.

If distributing built kernel modules or upstream application binaries, include their corresponding source and applicable licenses. The repository's pinned source URLs, patches, configuration, and build recipe identify the module's inputs. Do not redistribute a binary alone while omitting its source obligations.
