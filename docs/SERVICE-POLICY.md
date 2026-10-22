# MuMu service permissions

## Why MuMu needs policy changes

The supported MuMu image starts with SELinux permissive. Its virtual-hardware services therefore perform operations absent from the vendor policy. Switching to enforcing without repairing those dependencies blocks real functionality.

This project assigns service identities and file labels, then grants the necessary interfaces. The kernel enforces the resulting policy. KernelSU's root authorization and SELinux hiding are separate from these permissions.

## Permission groups

| Function | Processes/domains | Access |
| --- | --- | --- |
| Graphics and media buffers | SurfaceFlinger, system server, audio/camera/media services and relevant virtual-hardware HALs | Read MuMu runtime configuration; use `/dev/vaddress` with the driver's `0x4c15–0x4c1a` control commands |
| Service discovery and callbacks | `nemuinit` and `powerbtnd` in `init`, Android service manager | Binder calls/handle transfers in both directions and process-context lookup |
| Runtime device creation | Kernel devtmpfs worker | Create nodes when MuMu recreates virtual input devices |
| Native mouse and keyboard | `nemuinput`, running in `init` | Open/read/write the vendor-labeled input device; use the `0x55` uinput control-command family |
| Toolbar recent apps | MuMu's native bridge in `init` | Execute the `input` shell wrapper and `cmd` dispatcher with `shell_exec` labels; find Android's input service |
| Performance management | `nemu_sys_opt`, running in `init` | Read CPU/I/O pressure counters and control the vendor's `/proc` VM tunables; read network-interface metadata in sysfs |
| Crash reporting | `crash_dump` | Read MuMu runtime configuration |
| App isolation | Ordinary app and isolated-process domains | No additional permissions from the v1.0.3 service repair |

The graphics/media list is explicit in `profiles/mumu-pro-1.9.2-arm64/hardening/policy-v1.0.3.rules`. It covers services that can allocate buffers after startup, rather than only processes seen opening the driver during boot.

MuMu's native helpers share the `init` domain in this integration. Their additional permissions therefore apply to that domain, not exclusively to one executable. In particular, this vendor labels its VM tunables with the general `proc` type; the performance-management grant expands `init` access to that type. It does not give apps that access. This is a compatibility tradeoff, not a claim of stock-phone policy equivalence or Android certification.

No app domain is made permissive. The repair adds no blanket allow rule across all objects or domains. The privileged KernelSU domain remains privileged by design.

## Fixed failures in v1.0.3

- **Scene/video crashes:** the media decoder could not open MuMu's graphics connection. Video buffer import failed, then the game's JNI error handler aborted. The repair covers the decoder and other trusted graphics/media clients.
- **Mouse/keyboard stops responding:** `nemuinput` was denied writes to `/dev/uinput`. ADB-generated touches did not exercise this path. The repair includes both ongoing input and device recreation after service restart.
- **Native-service restarts:** startup in permissive mode masked missing service-manager handle/callback permissions. The repair covers Binder reconnection and network-interface discovery under enforcement.
- **Optimizer restart crash:** the vendor helper treated an existing control group as a fatal error. A version-locked binary patch accepts only `EEXIST` for that mkdir call and retains the original handling of other errors. It reuses the kernel-owned group instead of moving or killing its worker. The original vendor binary is not redistributed.
- **Performance monitor and diagnostic denials:** required pressure-counter, VM-control and runtime-configuration access was missing.

The installation check now includes 18 persistent core, media and hardware services. A service being `running` is not proof that every function works; release qualification also exercises native input, decoder output, audio, sensors and networking. See the separate [validation record](VALIDATION.md) for measured coverage and remaining limits.

## Service lifecycle

### Recent-apps toolbar repair

The toolbar's recent-apps button runs `/system/bin/input`, which invokes `cmd input`, from MuMu's native bridge in the `init` domain. The original `system_file` labels prevent execution under enforcement; after execution is allowed, service discovery also needs `init` access to `input_service`. An ADB `input keyevent KEYCODE_APP_SWITCH` test uses the `shell` domain and can succeed while the native button remains broken.

The repair labels only `/system/bin/input` and `/system/bin/cmd` as `shell_exec`, reusing the existing permission for shell-command execution, and adds `allow init input_service service_manager find`. It does not grant `init` execution of every `system_file`. File-context entries and explicit label verification make the repair persistent and checkable. The updater checks the previous file and patch hashes before replacing the label table; both known v1.0.3/v1.0.4 policy serializations are accepted.

Test the actual MuMu toolbar button after a cold boot, repeat it from both Home and an app, and exercise Clear All. Also verify ADB input and package commands still work. Keep SELinux enforcing throughout these tests.

### Restarting services

MuMu's Android framework caches its central `nemuinit` Binder connection. Forcibly restarting that bridge in isolation can produce a `DeadObjectException` in `system_server` and an Android reboot. Use a full MuMu stop/start for central-bridge changes; the installer does this. This vendor lifecycle limitation is not fixed by broader SELinux permissions. The supported hot-restart checks cover input, graphics cleanup, the repaired optimizer and the power-button helper.

## Troubleshooting

1. Run `python3 ksu.py verify-hardening --instance INDEX`. A fallback, unexpected file hash or stopped required service is a failed check.
2. Identify whether Android is alive but native input is blocked, a single app crashed, or the VM restarted. These require different fixes.
3. Read the new tombstone and logs immediately after a failure. A JNI error alone does not identify its upstream cause.
4. Correlate an SELinux denial with the failed service, resource and operation. Ordinary apps being denied private files is expected; do not turn every denial into an allow rule.
5. Repair the complete interface needed by the responsible service. Test initial use, repeated use, service restart and cold boot, plus an app operation that must still be denied.

Keep SELinux enforcing while testing a qualified repair. The “Hide SELinux modification” switch changes selected observations; it does not supply missing permissions or fix a broken service.

## Maintaining the policy

The full fresh-install policy is `hardening/policy.rules`. Reviewed migration rules and input/output hashes are listed in `hardening/policy-migrations.json`.

`update-policy` verifies the previous installation, compiles the reviewed change with the pinned policy utility, checks the resulting hash, applies it live, installs it and any fingerprinted helper repair on the private system disk, restarts a replaced helper to release its old executable, and restores `/system` to read-only. It preserves user SELinux-hiding preferences. It creates no recovery copy; compiler/staging files are removed.

Fresh compilation and migration can serialize an equivalent policy differently. Only individually pinned outputs are accepted. Their rules, type attributes and ordinary-app permissions are compared with SETools before qualification. Unknown output is rejected.
