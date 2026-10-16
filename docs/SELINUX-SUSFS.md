# SELinux enforcement and SUSFS on MuMu

The complete configuration combines the working Next root port, a separate MuMu-specific SUSFS LKM, and persistent SELinux repairs. These are independently fingerprinted components. The supported target is the exact MuMu Pro 1.9.2 ARM64 build in the profile.

## Why the initial enforcing trial failed

The first timed test correctly demonstrated that MuMu's policy was not ready for enforcement: the shell could not launch, graphics/sensor services lost driver access, and the watchdog restored permissive mode. These were repairable integration faults.

The repair addresses their causes:

- System files receive their intended SELinux labels. PID 1 runs in the `init` domain, and standard Android services receive explicit service identities.
- MuMu's virtual driver gets a dedicated `mumu_vaddress_device` type, including the MLS attribute needed by apps with distinct category labels. Its actual clients receive the necessary file operations and **only driver ioctl commands `0x4c15`–`0x4c1a`**, derived from the vendor driver's dispatch code.
- MuMu's per-app configuration, shared libraries, app logs, properties and private Binder services receive specific types and permissions. The graphics cleanup executable gets its own execution label so it can restart after enforcement begins.
- Protected vendor library trees are labeled on the stopped instance's ext4 filesystem. The tool verifies every modified extended attribute, runs filesystem checks, checks the rebuilt QCOW2, and swaps it only while that instance remains stopped.
- KernelSU's early daemon runs through its absolute installed path, which triggers the intended transition into the privileged KernelSU domain. The original relative invocation left helper processes in an unsuitable domain.

There is no blanket `allow appdomain * * *`, and no change making all app domains permissive. The root domain is privileged by design. An ordinary app was tested accessing a world-readable file labeled `system_data_file`: it receives `EACCES` while its UI, touch input, sensors, HTTPS and muted audio playback continue to work. The same app can launch an authorized root child without turning its ordinary process into a globally privileged app.

## Policy compiler pin

The installer downloads the official **Magisk v27.0 APK solely to extract `magiskpolicy`**, checks both hashes, and uses that standalone policy utility. It installs neither Magisk root nor Magisk Manager.

This older utility is an intentional toolchain pin. The inspected [v30.7 parser](https://github.com/topjohnwu/Magisk/blob/e8a58776f1d7bdf852072ad0baa6eceb9a1e4aac/native/src/sepolicy/statement.rs) strips `0x` and then uses decimal parsing. We reproduced an intended `0x4c15`–`0x4c1a` rule becoming ioctl `0` in the resulting policy. The [v27.0 utility](https://github.com/topjohnwu/Magisk/tree/2c6adbc69ba0e5dce09cd13c6d9aca5de30efe76) compiled the intended values, independently inspected with SETools `sesearch`, and passed real enforcing boots.

The specification pins **both the original vendor policy and the resulting compiled policy hashes**. A compiler exiting successfully is insufficient. Updating this tool requires semantic inspection and runtime qualification, not changing an APK version string.

## Which SUSFS implementation is installed?

This uses [inforcqb/susfs4ksu-lkm](https://github.com/inforcqb/susfs4ksu-lkm) at pinned legacy commit `0b197bfd3d3402ee108e19c66ed3293d9d14481a`, plus this repository's 4.19 port. It implements the SUSFS control protocol as an independent loadable engine. It is **not the canonical SUSFS patches compiled into a replacement MuMu kernel**, and is not claimed to have identical internals or universal feature parity.

The standard `mumu_susfs` KernelSU module ZIP contains the engine, a small control client, and startup and failure-detection scripts. It uses the official Next daemon's loader and SUSFS queries. Next's embedded GKI SUSFS autoload is disabled because those binaries do not match MuMu's kernel.

The port adapts old procfs, syscall, page-walk and memory-access APIs; uses the actual 4.19 namespace lock; and defers namespace work out of probe context. A real optional mapped-file test found a wrong `get_user_pages_remote` argument assumption. That was fixed for the old task/mm/start signature and retested, including maps, smaps, pagemap and `/proc/self/mem` observations. Compile-time prototype checks preserve that assumption visibly.

The path filters additionally run before directory entries are copied to userspace, handle `O_PATH`, and reject protected inodes before Unix permission checks. They preserve the original file modes, including `0600`, instead of making protected files more permissive.

## Defaults and tested features

By default the module hides the KernelSU module listing and registered root/policy paths from applicable unprivileged processes, and enables the engine's mount-hiding support. It does not install Zygisk, a metamodule, an integrity-spoofing module, or an arbitrary collection of extra kernel extensions.

| Capability | Observed behavior / boundary |
| --- | --- |
| Root authorization | Official Manager grants; unapproved app denied, approved root child succeeds |
| Path controls | Registered files disappear from stat, ordinary open, `O_PATH` and directory enumeration for test app identities; root retains access |
| Unix permissions | Original `0644` and `0600` modes unchanged |
| Concurrent directory/path checks | 72,000 path operations and 10,000 directory reads with a concurrent userspace buffer observer; no observed registered-name leakage or missed probes |
| Mount controls | Test bind mount hidden from the app's mount list; fdinfo reports the visible parent mount; root retains the real view; 30 new namespaces exercised |
| Metadata controls | Selected inode/size values changed for an unprivileged process; root retained actual metadata |
| Mapped-file controls | Selected maps/smaps entries hidden; pagemap entry zeroed; `/proc/self/mem` read blocked; root retained access |
| Open redirect | Test app read replacement bytes while root read the original; displayed fd path retained original name |
| Uname control | Tested changing the reported release while the privileged kernel sysctl retained the real identity; reset afterward |
| Module lifecycle | Standard Next module installation, boot stages, disable/re-enable and cold-boot verification |

See [the validation record](VALIDATION.md) for release evidence. Version/feature-query output alone is not behavioral proof.

## Known boundaries

- An LKM adds observable surfaces and bounded probe capacity. Zero misses in the stated stress test is a measured result, not a mathematical guarantee under unlimited load.
- A hard-link or symlink alias still has a directory entry unless that alias is registered; access to its protected target is denied. The directory filter uses inode plus registered name because its callback does not expose a filesystem identity. Do not claim arbitrary aliases are all invisible.
- Open redirect by itself does not make replacement-file inode metadata identical to the original. Metadata controls are separate.
- The old kernel has no modern `statx` mount-ID field. This port does not invent that interface.
- Some upstream UID schemes and optional APIs are not equivalent to canonical in-tree SUSFS. Advanced control changes require their own app/namespace tests. Custom command-line spoofing and third-party injection/mount modules are outside this release's behavioral guarantees.
- MuMu remains an emulator. Root hiding and SELinux enforcing do not create a certified physical device, a locked trusted boot chain or hardware-backed attestation. See [Google's verdict documentation](https://developer.android.com/google/play/integrity/verdicts).
- The policy repair is an engineering improvement to this vendor environment, not Android CTS certification or an independent security audit of MuMu.

## Boot guards and the v1.0.1 startup repair

The enforcing watchdog records the boot ID before enabling enforcement. Success now requires **ten consecutive seconds with all nine essential services running**: zygote, SurfaceFlinger, vold, netd, nemuinit, nemuinput, nemu_sys_opt, opengl-gc and powerbtnd. The marker runs asynchronously so init can continue starting services. An Android boot-completed property alone is insufficient.

The earlier recipe allowed initial startup but omitted execution labels needed when MuMu's core helpers restarted under enforcement. A real guest log showed repeated nemuinit restart denials and a subsequent `vold-failed` reboot. v1.0.1 adds the dedicated core executable type, narrow socket/property/configuration rules and replacement platform startup. App, driver and cold-boot checks passed after the repair.

If startup takes too long, the watchdog restores the prior mode; an unfinished prior boot causes a flagged fallback. `verify-hardening` checks the actual kernel flag, current boot marker, fallback property, installed hashes, labels, init domain and essential services. Next's SELinux-status and AVC masking are disabled. A fallback is a failed verification, never claimed as successful enforcement.

SUSFS has a separate pending-boot guard with synchronized marker writes. Disable **MuMu SUSFS** in Next's Modules screen and cold-boot to remove the running engine. Safe hot-unload is not supported.

These guards create no backup. Maintenance keeps small diagnostic records and removes temporary working files; there is no restore command or retained disk/instance copy. Investigate the failed check before retrying instead of repeatedly clearing markers to force the same failing boot.
