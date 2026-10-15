# Third-party components

This repository's original Python, shell, and verification code is MIT-licensed. Kernel patches are GPL-2.0-only.

The build downloads and modifies these components:

| Component | Pinned source | License |
| --- | --- | --- |
| Android common kernel headers/build infrastructure | [f931d3c](https://github.com/aosp-mirror/kernel_common/tree/f931d3c324845b1be4337d27b565351fb581f206) | Linux kernel GPL-2.0 with upstream file-level exceptions |
| KernelSU Next kernel implementation | [c81cdf5, legacy branch](https://github.com/KernelSU-Next/KernelSU-Next/tree/c81cdf51c3bb606836c6fc9a7cc858053eb0bc62) | GPL-2.0-only |
| Independent SUSFS LKM and control client | [legacy 0b197bf](https://github.com/inforcqb/susfs4ksu-lkm/tree/0b197bfd3d3402ee108e19c66ed3293d9d14481a) | GPL-2.0; derived components retain upstream notices |
| KernelSU Next Manager and ksud | [v3.4.2](https://github.com/KernelSU-Next/KernelSU-Next/tree/v3.4.2) | GPL-3.0-or-later and upstream component licenses |

The upstream KernelSU project by weishu and KernelSU Next contributors provide the root implementation. This repository supplies the measured MuMu ABI adaptations, orchestration, and validation. It is not affiliated with NetEase or either upstream project.

MuMu's `Image`, proprietary driver binaries, APKs, and VM disks are not checked into this repository. The configuration records observed kernel build options; it contains no emulator account or device identity data.

If distributing built kernel modules or upstream application binaries, include their corresponding source and applicable licenses. The repository's pinned source URLs, patches, configuration, and build recipe identify the module's inputs. Do not redistribute a binary alone while omitting its source obligations.

SELinux repair downloads the official Magisk v27.0 APK solely to extract the GPL-3.0 standalone policy utility. The installer pins its APK/binary hashes and [source commit](https://github.com/topjohnwu/Magisk/tree/2c6adbc69ba0e5dce09cd13c6d9aca5de30efe76). The release does not redistribute that APK or utility, and does not install Magisk root.
