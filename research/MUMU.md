# MuMu / KernelSU research

Research and experiments performed on 2026-10-15. Statements marked **observed** came from the installed MuMu build or controlled test instances. The implementation is specific to that measured build.

## Result and selected method

The working method is a **KernelSU Next legacy LKM compiled against Android common 4.19.195 with MuMu ABI corrections**, loaded at Android's `post-fs-data` stage. This preserves the vendor kernel, graphics driver, and emulator-specific behavior. It does not require an arbitrary replacement kernel, a standard Android `boot.img`, or modifications to the host hypervisor.

| Approach | Finding |
| --- | --- |
| Install Manager APK only | Provides UI; does not add the kernel implementation. |
| Copy files into a system disk only | Useful for persistence, but a compatible kernel component must actually load. |
| Flash an official modern GKI module/image | Does not match this 4.19 vendor kernel. |
| Rebuild and replace MuMu's entire kernel | Requires reproducing vendor functionality and driver ABI. Unnecessary for this target because an LKM works. |
| Patch a compatible LKM and load it through init | Verified: Manager, kernel control API, authorized root, and persistent boot execution. |

Upstream KernelSU documents custom integration for non-GKI kernels and identifies v0.9.5 as the last upstream version supporting that path. That version provided the first successful proof here. The final implementation uses KernelSU Next's newer legacy branch instead. [KernelSU non-GKI guide](https://kernelsu.org/guide/how-to-integrate-for-non-gki.html), [pinned Next legacy source](https://github.com/KernelSU-Next/KernelSU-Next/tree/c81cdf51c3bb606836c6fc9a7cc858053eb0bc62).

## Observed boot architecture

MuMuPlayer Pro 1.9.2 ships these resources inside its nested Android Device application:

```text
vms.bundle/Contents/Resources/
    Image
    initrd.img
    system.qcow2
    data.qcow2.gz
```

`Image` is a raw ARM64 Linux image. `initrd.img` is gzip-compressed newc CPIO. Its outer BusyBox init mounts a second ramdisk and the Android system/data filesystems before switching into Android init. The live guest had no `/dev/block/by-name` directory. A generic phone boot-image flashing procedure does not describe this layout.

Putting a modified `initrd.img` in the laboratory instance directory did **not** change the booted ramdisk: the diagnostic marker was absent from the console. The final implementation therefore uses an imported Android init file on the instance's private system disk.

MuMu provides `mumutool` for explicit instance selection, creation, lifecycle management, ADB ports, root, and system writability. Its documented `systemWritable` option maps to `systemFilePermissionType=1` in the observed build. Enabling it created a private `system.qcow2` for the selected instance. [MuMu's developer documentation](https://www.mumuplayer.com/help/mac/developer-support-function.html).

## Observed kernel properties

The full profile and hashes are in [profile.json](../profiles/mumu-pro-1.9.2-arm64/profile.json). Relevant configuration:

```text
CONFIG_MODULES=y
CONFIG_KPROBES=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_SECURITY_WRITABLE_HOOKS=y
CONFIG_ARM64_4K_PAGES=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SIG is not set
# CONFIG_RANDOMIZE_BASE is not set
```

The loaded vendor `vaddress.ko` contained DWARF debug information. Comparing it, and the vendor XFS module, with builds of the Android common source established matching layouts for important structures including `cred`, `module`, `file`, `inode`, `dentry`, and `vm_area_struct`.

The critical difference was in `task_struct`: MuMu adds a pointer and a 12-byte scheduling structure after `files`, followed by alignment. The net insertion is **24 bytes**. Measured offsets include `files=1728`, `nsproxy=1760`, `seccomp=1880`; total `task_struct` size is 3712 bytes. A module built without the correction accesses the wrong fields after that insertion. The patch reserves the measured space; it does not reproduce proprietary functionality.

This is an ABI reconstruction backed by measurements and runtime tests, not a claim to possess MuMu's complete kernel source. The vendor's third-party page linked modified QEMU sources, which were inspected, but did not supply the matching Linux kernel source in that archive. [Vendor source disclosure page](https://www.mumuplayer.com/mac/license/licenses.html).

## Why source and symbol matching both matter

Linux's external module build process depends on the target configuration and headers. `modules_prepare` alone does not produce symbol CRCs for a kernel using `CONFIG_MODVERSIONS`. This target has that feature disabled, so the build can prepare headers and compile an external module without rebuilding the complete vendor kernel. That does **not** remove the need to match structure layouts. [Linux external module documentation](https://docs.kernel.org/kbuild/modules.html).

The initial KernelSU 0.9.5 build referenced 13 existing but unexported kernel symbols. A test ELF binder converted those unresolved entries to absolute symbols using the running kernel's symbol table. The modern Next build required more symbols; its official `ksud insmod` already implements runtime ELF symbol resolution, so the final installer uses that maintained implementation. It resolves addresses again each boot, rather than distributing an address-bound module. [KernelSU module loader implementation](https://github.com/tiann/KernelSU/blob/0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d/userspace/ksuinit/src/lib.rs).

Merely finding a symbol is insufficient. One initial Next load failed while resolving a call to `security_add_hooks`; the symbol belongs to freed kernel initialization memory. The port registers its LSM hooks directly into this build's writable lists and pins the module to prevent unsafe unloading.

## Necessary Next patches

The final patch set addresses these observed compatibility gaps:

1. Correct MuMu's 24-byte `task_struct` ABI displacement in the build headers.
2. Reuse the vendor-exported stack guard; avoid the upstream module's private guard initialization wrapper.
3. Preserve MuMu's existing SELinux enforcement mode. The tested vendor environment is permissive; forcing enforcement during a late load is a separate system-policy change.
4. Register LSM hooks without calling freed `__init` code, and require reboot for removal.
5. Add the missing reboot syscall control hook to the legacy syscall-table backend so userspace can obtain its KernelSU control file descriptor.
6. Read the filename pointer from kernel `pt_regs` correctly.
7. Check `execveat`'s fifth argument for flags, rather than its fourth argument, which is `envp`.
8. Use fault-capable pathname reads in normal syscall context. The no-fault path failed for a freshly forked shell; a ptrace experiment that populated the page made the same call succeed, isolating the faulting behavior.
9. Use the vendor's existing `ksys_umount` path rather than assuming a build-tree `path_umount` backport exists in the running kernel.

See [the complete Next patch](../patches/kernelsu-next-mumu.patch) and [ABI header patch](../patches/mumu-task-layout.patch).

## Persistence and authorization

The installer places the unbound module and matching daemon in `/system/etc/ksu-emulator` and publishes `/system/etc/init/ksu-emulator.rc` last. At boot, the script verifies the exact kernel identity, compressed configuration hash, and payload checksums before loading the module. It runs the usual post-fs-data, services, and boot-completed stages.

The root toggle is used only to bootstrap installation. With it disabled, ADB returns UID 2000. A fresh unapproved shell was denied root, while an approved shell obtained UID 0 with the `u:r:ksu:s0` domain. This distinguishes KernelSU-controlled access from MuMu's original `su`.

## Other emulator families

Android Studio's emulator supports selecting a kernel explicitly with `-kernel`, which makes custom GKI/rebuilt-kernel experiments straightforward compared with MuMu's resource layout. The connected local Android Studio instance used Android 15 / ARM64 / kernel 6.6; it was inspected but not modified. [Android Emulator command-line reference](https://developer.android.com/studio/run/emulator-commandline).

Windows MuMu uses a different architecture and boot layout. Windows Android 15 versions have also been reported with a vendor KernelSU implementation; that is not evidence of compatibility with this macOS module. Windows installation is not implemented here. Modern x86_64 kernel syscall hardening introduces additional KernelSU-specific requirements, documented upstream. [KernelSU x86_64 support](https://kernelsu.org/guide/x86_64-support.html).

## Subsequent enforcement and SUSFS work

The core installer still preserves the vendor mode described above. The separate `enhance-clone` workflow now repairs the vendor policy/labels and provides genuine enforcement with an independently ported SUSFS LKM. See [the implementation and limitations](../docs/SELINUX-SUSFS.md) and [validation](../docs/VALIDATION.md).
