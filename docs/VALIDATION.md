# Validation record — 2026-10-15

Target: MuMuPlayer Pro 1.9.2, Apple Silicon, Android 12, kernel `4.19.195-android-arm64-gedae1315d023`. See the profile for exact image and configuration hashes.

## Completed runtime checks

| Check | Result |
| --- | --- |
| Legacy upstream KernelSU proof | v0.9.5 kernel API returned 11872; manager showed Working; authorized shell obtained UID 0 |
| Current implementation | Custom Next legacy module + official v3.4.2 Manager/daemon |
| Kernel control protocol | `version=33355`, `uapi=5`, flags identify LKM + late-load |
| Manager UI | Working, LKM (GKI1), v3.4.2; custom/jailbreak labels accurately reflect the load method |
| Standard shell root | `su -c id` returns UID 0, `u:r:ksu:s0` after authorization |
| `execveat` | Explicit native `execveat(AT_FDCWD, ...)` root test passes |
| Native test process | UID 2000 before su, UID 0 afterward |
| Vendor root disabled | ADB is UID 2000; authorized KernelSU root still works |
| Unauthorized shell | A fresh installation denies su before the Shell profile is authorized |
| Cold boot persistence | Init hook loads the module and reports ready across full stop/start cycles |
| KernelSU module scripts | Smoke module ran post-fs-data, service, and boot-completed once for the same boot ID |
| Clean build | Pinned sources + included patches built in a fresh Docker toolchain container |
| Automated installer | Completed on a separate fresh instance, including two cold boots and vendor-root shutdown |
| State-change handling | Installation aborted on a changed device state and automatically restored its system/settings |
| Explicit recovery | Restored a pre-existing private system disk; a baseline marker survived; KernelSU and its manager were removed; original root/writability settings were restored |

The native control probe returned:

```json
{"version":33355,"flags":5,"uapi":5,"uid":2000}
```

The authorized root check returned:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
Kernel Version: 33355
```

![KernelSU Next working inside a fresh MuMu instance](images/working.png)

The smoke module contained no system replacements and required no metamodule. Filesystem-mounting modules and every third-party module have **not** been validated. A metamodule may be needed for their mounting behavior, as shown by Manager's status.

## Host checks

The unit suite exercises ELF metadata parsing, malformed and truncated ELF rejection, archive path traversal rejection, exact guest identity checks, explicit instance selection, bundle integrity gates, and recovery identity/backup checks. Shell scripts pass syntax checks and Python modules compile.

GitHub CI runs host checks on Linux, macOS, and Windows. Those jobs do not imply Windows MuMu support. The manual build workflow cross-compiles the ARM64 module on Linux. Guest runtime testing requires the actual verified MuMu image.

## Limits of this validation

This establishes functionality on the fingerprinted MuMu build, not ABI compatibility with every 4.19 kernel or long-term stability of arbitrary root modules. The kernel module uses a measured vendor ABI adaptation. Preserve recovery receipts and add new profiles only after repeating the porting workflow.
