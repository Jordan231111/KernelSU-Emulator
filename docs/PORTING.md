# Adding an emulator profile

A profile must describe a measured kernel, not just an Android version or product name.

1. Collect `uname -r`, `uname -v`, CPU architecture, `/proc/config.gz`, module metadata, and the boot layout. Use `probe` before making changes. Keep device identifiers and personal filesystem data out of committed reports.
2. Identify the kernel source base and compare structure layouts with vendor DWARF/BTF where available. A matching release string alone is insufficient. Recover actual field offsets before loading a module.
3. Compile against the target configuration. Inspect undefined symbols, function prototypes, structure sizes, stack-protector behavior, and module versioning/signatures. Reject missing symbols and references into freed init code.
4. Test on the explicitly selected emulator instance. Prove the KernelSU control API and an allowed non-root UID becoming root. Prove a denied UID stays denied with vendor root disabled.
5. Verify manager authentication, ordinary shell execution, `execveat`, cold boots, boot scripts, and failure reporting. Test graphics and Android startup after the kernel integration. Maintenance creates no backup or recovery copy and performs no disk rollback.
6. Add immutable source revisions and SHA-256 checksums. Extend the profile loader and build script's explicit target list only after those tests pass. Extend the build recipe and qualify runtime behavior for each additional target.

For a modern GKI target, investigate the upstream module and KMI path first. For a vendor non-GKI target, retaining its kernel can preserve emulator drivers, but requires measured ABI compatibility. Replacing a whole kernel remains an option when the necessary vendor source and boot path are available.

The current MuMu profile uses a Docker Linux toolchain and an Android common source base. Its build-time structure padding matches that measured kernel; remeasure the offsets when changing targets.

### KernelSU legacy upgrade, 2026-11-20

The selected kernel pin is `e5f5ec998de88b9fc43c62cff8f7ae12d3f4800a`, the current legacy head checked on November 20. Its SELinux locking change applies to this pre-5.10 kernel. The credential-accounting change for 5.14+ and x86-64 alignment change do not apply to this ARM64 4.19 target. [Upstream revision comparison](https://github.com/KernelSU-Next/KernelSU-Next/compare/c81cdf51c3bb606836c6fc9a7cc858053eb0bc62...e5f5ec998de88b9fc43c62cff8f7ae12d3f4800a)

The original two rejected hunks have been rebased. Upstream already uses `READ_ONCE(*filename_user)` for the kernel pointer; the duplicate local change was removed. MuMu still needs fault-capable pathname reads, the correct `execveat` argument slot, late LSM insertion, stack/preemption adaptations and the reboot control hook.

The unresolved import was **`path_umount`**. Upstream's Kbuild backported it into the build source, which cannot add it to MuMu's running Image. The patch omits that backport and selects the existing `ksys_umount` path. All **206** imports in the resulting module match the measured kernel; the preceding published core had 209.

An initial linked build exposed UAPI 6. Released Manager/ksud v3.4.2 requires UAPI 5 exactly and skips module boot stages on a mismatch, despite returning success. The MuMu patch therefore keeps the compatible UAPI 5 contract; the optional new symbol/preinit interfaces are not part of this deployment. The boot script verifies this contract before calling ksud. With that fix, instance 0 completes enforcing startup and runs its modules. Manager and daemon remain the latest signed release, v3.4.2; the kernel source revision is recorded separately from the release version code.
