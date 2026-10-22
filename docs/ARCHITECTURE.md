# Architecture

## Boot sequence

1. MuMu boots its original kernel and virtual hardware.
2. The instance's private system disk supplies `ksud`, `kernelsu.ko`, and the startup entry.
3. Startup verifies the kernel and payload fingerprints, then loads KernelSU.
4. KernelSU Next's Manager controls root authorization and module startup.
5. The MuMu SUSFS package loads its engine and default hiding rules.
6. The SELinux setup applies labels and service permissions, enables enforcement, and checks startup health.

Root applies to the Android guest. The modules target the exact kernel and driver fingerprints in the profile. Remove modules through a cold boot; hot-unload is unsupported.

## Components

| Component | Purpose |
| --- | --- |
| MuMu kernel and drivers | Preserve the emulator's virtual-hardware interfaces |
| KernelSU Next legacy port | Provide root on MuMu's 4.19 ARM64 kernel |
| Official Next Manager/daemon | Manage app authorization and module startup |
| MuMu SUSFS LKM | Filter selected filesystem, module, and mount observations |
| SELinux compatibility policy | Allow required virtual-hardware operations while retaining app isolation |
| `ksu.py` | Install, verify, and maintain one selected instance |

## Storage

MuMu's **Writable** setting selects the instance's private system disk. Selecting Readonly bypasses the installed files. Android normally mounts `/system` read-only; maintenance remounts it only while replacing checked files.

The tools operate in place without backups, clones, or disk rollback. Boot guards report failed startup and can skip enforcement or SUSFS on the next boot. Verification treats fallback as a failure.

## Vendor-root cleanup

The cleanup command removes recognized MuMu su/console helpers and their startup actions. A replacement startup helper launches the normal emulator API service without its su-dependent boot receiver. Graphics, input, and hardware services remain installed.

## SELinux and SUSFS

The supported MuMu image starts permissive. The compatibility policy supplies service identities, labels, and virtual-hardware permissions needed for enforcement. [Service policy](SERVICE-POLICY.md) describes their scope.

The SUSFS engine is an adapted independent LKM. It hides configured root/policy paths and module names and enables mount filtering. [SELinux and SUSFS](SELINUX-SUSFS.md) describes settings and limitations.

## Runtime logs

The four startup logs in `/data/adb/ksu-emulator` are `boot.log`, `policy.log`, `susfs.log`, and `platform-service.log`. Startup and boot-completion actions trim each to its newest 64 KiB. There is no background watcher or archive. Android and third-party app logs retain their own policies.
