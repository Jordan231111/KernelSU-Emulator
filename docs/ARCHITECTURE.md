# How it works

## Boot sequence

1. MuMu boots its original Android kernel and virtual hardware.
2. The selected instance's private system disk supplies a startup entry, the matching `ksud` daemon and `kernelsu.ko`.
3. Startup checks the kernel and payload fingerprints, then loads the KernelSU module.
4. KernelSU Next's Manager controls which apps may obtain root.
5. The separate MuMu SUSFS package loads its compatible engine and default hiding rules.
6. The SELinux setup applies the repaired labels and service policy, enables real enforcement and checks startup health.

Root applies to the Android guest. It does not root macOS.

## Components

| Component | Purpose |
| --- | --- |
| MuMu kernel and drivers | Keep the emulator's existing virtual-hardware interfaces |
| Custom KernelSU Next legacy port | Supply kernel root on MuMu's older 4.19 ARM64 kernel |
| Official Next v3.4.2 Manager/daemon | Manage root grants, app profiles and module startup |
| MuMu SUSFS LKM | Filter selected filesystem/module/mount observations |
| SELinux compatibility policy | Permit required virtual-hardware operations while retaining app restrictions |
| `ksu.py` | Install, verify and maintain the selected instance |

“Legacy” refers to the kernel integration branch. The Manager is the pinned official release. This port does not claim every feature of Next's modern GKI kernel branch.

## Why use loadable modules?

MuMu's kernel supports Linux loadable modules. Using that interface preserves its working kernel/driver combination. Replacing the whole kernel would also require reproducing MuMu's virtual-hardware interfaces.

The modules are built for the exact kernel and driver fingerprints in the profile. A module with the same filename or nominal kernel version is not interchangeable. Module removal requires a cold boot; safe hot-unload is not supported.

## Disk settings

MuMu's **Writable** setting selects a private system disk for the instance. The installer places its files there. Changing the MuMu setting to Readonly selects a different system view and bypasses those files.

Android can still mount `/system` read-only during normal operation. KernelSU does not require continuous filesystem write access. Maintenance temporarily remounts it when installing checked files.

## Vendor-root removal

The cleanup command removes recognized MuMu su/console helpers and their startup actions. It replaces the companion app's obsolete su-dependent boot receiver with a startup helper for the normal emulator API service.

MuMu's graphics, input and hardware services remain installed. They are virtual-hardware components, not competing root frameworks.

## SELinux

Enforcing means the kernel blocks operations that the loaded policy does not allow. Permissive logs those violations but allows them. Disabled turns that SELinux layer off.

This MuMu image starts permissive and lacks permissions needed by some of its own services. The compatibility policy repairs service identities, labels and virtual-hardware access. Its grants are broader for the trusted services that need those interfaces; ordinary app permissions are not expanded by the v1.0.3 repair. See [service permissions](SERVICE-POLICY.md) for the exact scope and tradeoffs.

“Hide SELinux modification” changes selected app-visible observations. It does not toggle enforcement, grant a missing service permission or certify the device.

## SUSFS

The engine is an adapted independent LKM from `inforcqb/susfs4ksu-lkm`, not canonical SUSFS compiled into a replacement kernel. The KernelSU package supplies that engine, its control utility and boot scripts.

Default rules hide known root/policy paths and module names and enable mount filtering. Additional features require their own configuration and tests. The general sidex15 SUSFS controller/WebUI is not bundled or qualified with this port. Root hiding does not hide every emulator characteristic or create hardware-backed attestation.

## Maintenance

A compatibility profile pins the supported MuMu kernel, driver, source revisions and userspace components. `update-policy` applies known SELinux repairs. `upgrade` updates matched root payloads. Neither silently substitutes the newest upstream release.

Updates happen in place. No VM backup, clone or retained original file is created. Temporary working files are removed. Boot guards retain small status markers and report failed startup; a fallback is not reported as a successful enforcing installation.

The four project startup logs (`boot.log`, `policy.log`, `susfs.log`, and `platform-service.log` under `/data/adb/ksu-emulator`) retain the newest 64 KiB each. Startup and boot-completion actions trim oversized text logs in place. A log can grow while startup is still writing it; the completion actions trim it again. There is no polling service, rotated copy, or change to Android's crash-reporting configuration. Logs already below the limit are not rewritten.

Use [the update guide](UPDATING.md) for new MuMu, KernelSU Next or SUSFS versions. Test records and historical investigations are kept in [validation](VALIDATION.md) and `research/`.
