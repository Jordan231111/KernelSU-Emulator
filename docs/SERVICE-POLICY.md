# MuMu service permissions

The supported MuMu image starts with SELinux permissive. Its virtual-hardware services need additional identities, labels, and permissions to run under enforcement.

## Permission groups

| Function | Processes/domains | Access |
| --- | --- | --- |
| Graphics and media | SurfaceFlinger, system server, media services, and virtual-hardware HALs | Read runtime configuration; use `/dev/vaddress` with driver commands `0x4c15–0x4c1a` |
| Service discovery and callbacks | Native MuMu helpers in `init`, Android service manager | Binder calls, handle transfers, and process-context lookup |
| Device creation | Kernel devtmpfs worker | Create nodes for virtual input devices |
| Mouse and keyboard | `nemuinput` in `init` | Use the vendor-labeled input device and `0x55` uinput commands |
| Recent Apps toolbar | MuMu bridge in `init` | Execute `input` and `cmd` with `shell_exec` labels; find `input_service` |
| Performance management | `nemu_sys_opt` in `init` | Read pressure counters and network metadata; control vendor `/proc` tunables |
| Crash reporting | `crash_dump` | Read MuMu runtime configuration |

The full rules are in `profiles/mumu-pro-1.9.2-arm64/hardening/policy.rules`. MuMu's native helpers share the `init` domain, so their grants apply to that domain. Vendor VM tunables use the general `proc` label. These permissions retain app isolation but differ from a stock phone's policy. KernelSU's root domain is privileged by design.

## Toolbar commands

MuMu's Recent Apps button executes `/system/bin/input`, a shell wrapper for `cmd input`. The repair labels those two entry points `shell_exec` and lets `init` discover `input_service`. It uses the existing shell-execution permission rather than granting execution across all `system_file` objects.

Test the actual toolbar button from Home and an app, then test Clear All. ADB key events run in the `shell` domain and do not test the native bridge's permissions.

## Service lifecycle

The optimizer repair accepts an existing control group only for the fingerprinted vendor binary and the expected `mkdir` failure. It preserves handling of other errors.

For central bridge changes, use a full MuMu stop/start. The Android framework caches its `nemuinit` Binder connection; restarting that bridge alone can restart Android. Input, graphics cleanup, optimizer, and power-button helpers can be tested independently under enforcement.

## Troubleshooting

1. Run `python3 ksu.py verify-hardening --instance INDEX`. Check actual enforcement, fallback, file hashes, labels, and all 18 required services.
2. Reproduce the failed operation through its real input path. Distinguish a blocked button, app crash, and emulator restart.
3. Read the corresponding tombstone and recent SELinux denials. Match the service, resource, and operation before changing policy.
4. Test the repair after cold boot and repeated use. Confirm ordinary apps still fail protected-file access.

Keep SELinux enforcing while testing. The hiding switch does not supply missing permissions. Ordinary apps being denied private resources is expected.

## Policy maintenance

`update-policy` accepts only fingerprinted previous installations. It checks input files, patch hashes, and compiler output before publishing the policy, label table, boot files, and any vendor helper repair. It preserves the saved hiding preference, removes temporary staging files, and restores `/system` to read-only.

Equivalent compiled policies can have different serializations. Each accepted hash must be inspected independently, including type attributes, ioctl permissions, and ordinary-app rules. See [guest tests](../tests/guest/README.md) and [Updating](UPDATING.md).
