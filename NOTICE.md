# Third-party components

This repository's original Python, shell, and verification code is MIT-licensed. Kernel patches and the native Disk Cleanup daemon are GPL-2.0-only. The freestanding Disk Cleanup client is MIT-licensed; file-level SPDX notices identify both. The optional NeoZygisk compatibility patch retains GPL-3.0; the r2frida correction retains MIT. Frida bridge corrections target the existing upstream distribution and retain its upstream licensing.

The build downloads and modifies these components:

| Component | Pinned source | License |
| --- | --- | --- |
| Android common kernel headers/build infrastructure | [f931d3c](https://github.com/aosp-mirror/kernel_common/tree/f931d3c324845b1be4337d27b565351fb581f206) | Linux kernel GPL-2.0 with upstream file-level exceptions |
| KernelSU Next kernel implementation | [e5f5ec9, legacy branch](https://github.com/KernelSU-Next/KernelSU-Next/tree/e5f5ec998de88b9fc43c62cff8f7ae12d3f4800a) | GPL-2.0-only |
| Independent SUSFS LKM and raw control client | [main 761b930](https://github.com/inforcqb/susfs4ksu-for-lkm/tree/761b93083afd846858257221453bf306465042a3) | GPL-2.0; derived components retain upstream notices |
| Sidex universal SUSFS client | [14b5773](https://github.com/sidex15/susfs4ksu-binaries/tree/14b577368caf43c84577918f5d8ba6cae56c8d63) | AGPL-3.0; corresponding source is included in the SUSFS bundle |
| KernelSU Next Manager and ksud | [v3.4.2](https://github.com/KernelSU-Next/KernelSU-Next/tree/v3.4.2) | GPL-3.0-or-later and upstream component licenses |

The upstream KernelSU project by weishu and KernelSU Next contributors provide the root implementation. This repository supplies the measured MuMu ABI adaptations, orchestration, and validation. It is not affiliated with NetEase or either upstream project.

MuMu's `Image`, proprietary driver binaries, APKs, and VM disks are not checked into this repository. The configuration records observed kernel build options; it contains no emulator account or device identity data.

If distributing built kernel modules or upstream application binaries, include their corresponding source and applicable licenses. The repository's pinned source URLs, patches, configuration, and build recipe identify the module's inputs. Do not redistribute a binary alone while omitting its source obligations.

SELinux repair downloads the official Magisk v31.1 APK to extract the GPL-3.0 standalone policy compiler. The installer pins SHA-256 hashes for the APK and binary. [Corresponding Magisk source](https://github.com/topjohnwu/Magisk/tree/0972f67d97f9b6302b67c5171283330c74114b4a)
