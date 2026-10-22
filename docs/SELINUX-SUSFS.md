# SELinux and SUSFS

## Settings

- Keep real **SELinux enforcing**, MuMu's disk **Writable**, and vendor root **Off**.
- **Hide SELinux modification** can be On or Off. Both saved choices persist through reboot; the unset default is On.
- Keep **AVC spoofing Off**. This integration does not connect its audit hook.

The hiding switch sanitizes selected context/access queries and status counters. It does not disable access checks. Maintenance verifies the actual flag through a root-side read of `/sys/fs/selinux/enforce`.

## Enforcement

The compatibility policy gives trusted MuMu services the virtual-hardware access they require while retaining ordinary-app isolation. KernelSU's root domain is privileged. See [service permissions](SERVICE-POLICY.md) for the scope and shared-domain tradeoffs.

Installation compiles policy with the checksum-pinned `magiskpolicy` utility from Magisk v27.0. The utility is used only as a compiler; Magisk root and Manager are not installed. Compiler output hashes and permission semantics are checked separately.

## SUSFS package

The `mumu_susfs` KernelSU package contains the MuMu-compatible kernel module, `susfs-sc`, boot scripts, and payload checksums. At boot it hides the KernelSU/SUSFS module names, registers known root/policy paths, and enables mount filtering.

Defaults cover `/data/adb` and the installer's system paths. Additional modules and apps may need separate rules. Root authorization does not exempt an app's ordinary process from every filter.

This is an independent SUSFS-compatible LKM using protocol v2.3.0. It is not the full canonical in-tree implementation. No general controller/WebUI is bundled. Package visibility, emulator identity, injection traces, and hardware-backed attestation are outside its default coverage.

## Verification and removal

```sh
python3 ksu.py verify-hardening --instance INDEX
python3 ksu.py verify-susfs --instance INDEX
```

These commands check startup and identity. [Guest tests](../tests/guest/README.md) exercise enforcement and hiding behavior.

To stop loading SUSFS, disable **MuMu SUSFS** in Next's Modules screen and cold-boot. Keep SELinux enforcing. Do not hot-unload either kernel module.
