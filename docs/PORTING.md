# Adding an emulator profile

A profile must describe a measured kernel, not just an Android version or product name.

1. Collect `uname -r`, `uname -v`, CPU architecture, `/proc/config.gz`, module metadata, and the boot layout. Use `probe` before making changes. Keep device identifiers and personal filesystem data out of committed reports.
2. Identify the kernel source base and compare structure layouts with vendor DWARF/BTF where available. A matching release string alone is insufficient. Recover actual field offsets before loading a module.
3. Compile against the target configuration. Inspect undefined symbols, function prototypes, structure sizes, stack-protector behavior, and module versioning/signatures. Reject missing symbols and references into freed init code.
4. Test in a newly created emulator instance. Prove the KernelSU control API and an allowed non-root UID becoming root. Prove a denied UID stays denied with vendor root disabled.
5. Verify manager authentication, ordinary shell execution, `execveat`, cold boots, boot scripts, and rollback. Test graphics and Android startup after the kernel integration.
6. Add immutable source revisions and SHA-256 checksums. Extend the profile loader and build script's explicit target list only after those tests pass. Keep unsupported configurations read-only.

For a modern GKI target, investigate the upstream module and KMI path first. For a vendor non-GKI target, retaining its kernel can preserve emulator drivers, but requires measured ABI compatibility. Replacing a whole kernel remains an option when the necessary vendor source and boot path are available.

The current MuMu profile uses a Docker Linux toolchain and an Android common source base. Its build-time structure padding must never be applied to another kernel without rechecking the offsets.
