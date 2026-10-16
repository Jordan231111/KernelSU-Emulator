# Validation record — 2026-10-15

Latest results: [v1.0.3 observations](validation-v1.0.3.json). Earlier records describe the workloads actually exercised, not exhaustive compatibility. v1.0.3 adds the scene-decoder, native-input and service-lifecycle checks missing from the earlier qualification.


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
| GitHub cross-build | Linux x86_64 runner produced a byte-identical ARM64 kernel module; its native control probe was also executed successfully in MuMu |
| Automated installer | Completed on a separate fresh instance, including two cold boots and vendor-root shutdown |
| State-change handling | Exact target and payload checks reject mismatches; current in-place failures stop and report the selected instance |

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

The unit suite exercises ELF metadata parsing, malformed and truncated ELF rejection, archive path traversal rejection, exact guest identity checks, explicit instance selection, bundle integrity gates, offline partition bounds, vendor cleanup restrictions and update failure handling. Shell scripts pass syntax checks and Python modules compile.

GitHub CI runs host checks on Linux, macOS, and Windows. Those jobs do not imply Windows MuMu support. The manual build workflow cross-compiles the ARM64 module on Linux. Guest runtime testing requires the actual verified MuMu image.

The validated release module SHA-256 is:

```text
b97e681d79d41cbf0c69bf8a494f4e0dc647f6241005f99ccc3ab8a0fe60dc76
```

## Limits of this validation

This establishes functionality on the fingerprinted MuMu build, not ABI compatibility with every 4.19 kernel or long-term stability of arbitrary root modules. The kernel module uses a measured vendor ABI adaptation. Add new profiles only after repeating the porting workflow.


## Complete enforcing + SUSFS release qualification

The initial v1.0.0 qualification used isolated test instances, including fingerprinted system-file changes, compiled-policy verification, offline inode labels and normal KernelSU module installation. The final recipe was also exercised through a framework-only update. v1.0.1 uses the in-place workflow described below.

| Check | Observed result |
| --- | --- |
| Actual kernel enforcement | `/sys/fs/selinux/enforce = 1`; status/AVC masking disabled; no fallback |
| Init and executable labels | Init domain and every critical executable/driver label verified |
| Driver policy | Independent binary-policy inspection confirms ioctl range `0x4c15–0x4c1a` |
| Ordinary Android APK | UI ticks, touch events, accelerometer events, DNS, HTTPS 200 and muted AudioTrack frames advance |
| Enforcement canary | World-readable `system_data_file` denied with EACCES to the app |
| Ordinary app root | Denied before grant; official Next Manager grant enables UID 0 in `ksu`; revocation denies it again |
| Approved app isolation | Its ordinary process still fails the canary read while its root child succeeds |
| Graphics service | SurfaceFlinger functional; `opengl-gc` runs and can restart under enforcement |
| Native path checks | stat/open/O_PATH/listing controlled; root retains access; 0644/0600 modes unchanged |
| Concurrent path test | 72,000 operations, eight workers; 10,000 directory reads with concurrent output-buffer observation; zero observed registered-name leaks or missed probes |
| Mount test | Bind mount hidden from unprivileged mountinfo, fdinfo mapped to visible parent; root retains mount; 30 new namespaces pass |
| Kstat / redirect | Selected metadata changes and replacement reads behave as documented; root view unchanged |
| Mapped-file controls | maps/smaps entries hidden, pagemap entry zeroed, proc-mem read blocked; root access retained |
| SUSFS disable/re-enable | Official daemon module controls plus cold boots remove and restore the engine; root and enforcement remain functional |
| Repeated full boots | Three successive stop/start cycles pass app, root, SUSFS, label and enforcement checks, with vendor root disabled |
| Maintenance preparation | Explicit pinned Next candidate, copied optional recipes, stable content-based policy identity and zero-fuzz patch preflight exercised |

The SUSFS kernel module SHA-256 is:

```text
e21cbf3fd31e89a422025ac8be884ca5623b74b68ebc9925665e212671053736
```

The original core kernel-module hash above remains unchanged. The startup scripts and bundle/source manifests changed. See the release checksums for complete artifact identity and [machine-readable observations](validation-v1.0.0.json).

The observed zero leak/miss counts apply to the stated test workload. Hard-link/symlink directory entries, redirect inode metadata, optional APIs and emulator attestation have explicit boundaries in [SELinux/SUSFS details](SELINUX-SUSFS.md). The test does not certify every game, banking app, anti-cheat, Zygisk implementation or third-party module.

## v1.0.1 — startup repair, sole root provider and no backups

The migrated primary instance exposed a real restart problem: nemuinit could not restart after enforcement, the legacy companion receiver failed without vendor su, and a `vold-failed` reboot followed. The repair adds scoped executable/property/socket rules, removes the obsolete receiver from startup, and preserves the normal vendor API through a checked helper. Boot acceptance now observes all nine core services for ten consecutive seconds.

The private disk was examined offline. The fingerprinted vendor su backup helper and serial-console launcher were physically removed, vendor root service declarations and Magisk compatibility startup code were removed, and root aliases/Magisk files were checked absent. The old Magisk framework and modules were uninstalled before Next installation. Standalone user apps were preserved.

The complete configuration passed real app UI/touch/sensors, DNS/HTTPS, muted audio, an SELinux denial canary, authorized and unauthorized root, the native SUSFS suite, and repeated cold boots. `/system` mounted read-only while MuMu's private-disk setting remained Writable. The in-place core update was exercised on this configuration; it preserves the platform helper and waits for the strengthened health check.

Backup/restore and automatic clone functionality, saved original policy files and recovery-receipt requirements have been removed. Disk-edit temporary files are deleted after use. The module binaries are unchanged from v1.0.0; policy, startup, cleanup and host maintenance changed. See [v1.0.1 observations](validation-v1.0.1.json) for measured results. The v1.0.0 record remains historical evidence, not a description of current backup behavior.

After the final cold boot, a further **364-second observation with 13 samples** retained the same boot ID and system_server/nemuinit/SurfaceFlinger PIDs. Every sample was enforcing, and the final uptime was 545 seconds. The nine-service and vendor-cleanup checks passed at the end. This is the measured observation window, not a claim of unlimited uptime.

## v1.0.2 — user-controlled SELinux hiding

The v1.0.1 startup scripts reset SELinux hiding to Off after the official daemon loaded saved preferences. v1.0.2 removes those resets. The official Manager controls the setting; saved On and saved Off both survive cold boots. With no saved choice, the pinned legacy kernel's default is On. The exact previous guard script is migrated during `upgrade`, with unchanged policy/system-file/label checks before writing.

Runtime qualification exercised On, saved Off after cold boot, and saved On after another cold boot. In all three cases, actual enforcement, the nine core services, approved Shell root, denied ordinary-app root, SUSFS startup and vendor cleanup passed. The real Android APK continued rendering, receiving touch/sensor events, playing muted audio and completing HTTPS requests while the SELinux canary remained denied with EACCES.

The separate native app_zygote-domain probe demonstrated a real visibility difference: the KSU context was accepted with hiding Off and rejected with EINVAL with hiding On; a stock context remained valid and an invented context remained invalid. The KSU-related access response and app-visible policy counters were masked only with hiding On. Root retained its real view. The ordinary APK was denied direct access to the SELinux status interface in both modes; no policy exception was added to make that test pass.

Both kernel binaries and the compiled static policy are unchanged. See [the measured v1.0.2 observations](validation-v1.0.2.json). The public feature default and boot persistence were changed without making backups, cloning instances or adding root grants.


## v1.0.3 — media, native input and service compatibility

The original Another Eden crash was reproduced independently: H.264 decoding failed before the first frame because `mediaswcodec` could not open MuMu's graphics connection. After the service-policy repair, the generated clip delivered all 60 frames. The user also confirmed that the failing game scene played successfully.

The complete service repair covers trusted graphics/media clients, native input's normal uinput operations, kernel devtmpfs device creation, native Binder service-manager communication, performance counters/VM controls and diagnostic configuration reads. SETools comparison found no new permissive domains, unchanged type attributes and unchanged rules for the covered ordinary-app and isolated-process domains. Fresh-install and upgrade policy serializations were inspected separately and pinned by hash.

A separate vendor helper defect was exposed by lifecycle testing: `nemu_sys_opt` aborted when its existing control group caused `mkdir` to return EEXIST. The reviewed ARM64 edit handles that one errno as success and keeps all other errors on the original path. Its input matches the untouched MuMu application image. The patch extends an existing RX segment into unused padding without changing its permissions, and is gated by complete input/output hashes. The vendor binary is not distributed.

Final checks:

- Two full MuMu stop/start cycles with real enforcing, no fallback, matching installed hashes/labels and all 18 required services running.
- H.264 after both cold boots; final H.264 1080p, HEVC and VP9 runs each delivered 60 frames and reached end-of-stream.
- Native Mac keyboard input produced `ksutest`; native mouse input incremented the APK touch counter. The user confirmed both again after the final boot.
- Muted audio playback advanced, sensor events arrived and HTTPS returned 200. The world-readable SELinux canary remained inaccessible with EACCES. An unapproved app could not launch `su`; approved Shell root continued to work.
- Input, graphics-cleanup, optimizer and power-button services restarted under enforcement. App launch remained functional, the boot ID stayed unchanged and no relevant new denials were observed.
- Final root, SUSFS and vendor-cleanup checks passed, `/system` was read-only and the final boot was observed for more than ten minutes. Installed diagnostics and staging files were removed.
- 45 host tests passed. The vendor-cleanup check now distinguishes KernelSU injection add-ons from competing root-provider daemons.

The central `nemuinit` bridge is not an independently restartable component of this vendor framework: forcibly killing it leaves a cached Binder reference and can restart Android. Core maintenance therefore uses full MuMu cold boots. This limit remains documented rather than hidden by broad permissions. Camera enumeration was checked; physical camera/microphone capture and external Bluetooth hardware were not tested. These results are not CTS certification or a guarantee for arbitrary third-party modules/apps.
