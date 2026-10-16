# SELinux and SUSFS

## Recommended configuration

- Keep **real SELinux enforcing** after installing the compatibility policy.
- Keep MuMu's disk setting **Writable** and vendor root **Off**.
- Choose **Hide SELinux modification** On or Off in KernelSU Next. Both choices persist through reboot. With no saved preference, this port defaults to On.
- Leave Next's **AVC spoofing** Off. Its audit hook is not connected in this integration.

The hiding switch sanitizes selected SELinux context/access queries and status counters. It does not change the real enforce flag or disable access checks. A root-side read of `/sys/fs/selinux/enforce` is used for maintenance verification.

## What enforcing protects

Android's user IDs separate apps; SELinux adds restrictions based on process and resource labels. Enforcing applies those restrictions. It remains useful with root installed because ordinary app processes do not automatically become privileged.

The MuMu repair grants trusted services the virtual-hardware operations they require. Those services have more access than under the incomplete vendor policy. Ordinary app restrictions remain in place. This is not equivalent to a vendor-certified phone policy or a guarantee that every root extension is confined. KernelSU's own root domain is privileged by design.

See [service policy](SERVICE-POLICY.md) for which permissions change. Do not turn all SELinux denials into allow rules: denied app access to private resources is expected.

## What the SUSFS package does automatically

The `mumu_susfs` KernelSU package contains:

- The MuMu-compatible SUSFS kernel module.
- `susfs-sc`, its control utility.
- Boot scripts, target checks and payload checksums.

At boot it hides the engine/KernelSU module names, registers the known root and policy paths, and enables mount filtering. Ordinary app processes receive the applicable filtered view; privileged access follows the engine's rule-specific exemptions.

The defaults cover `/data/adb` and this installer's system-side root/policy paths. They do not automatically discover and conceal every trace left by additional Zygisk, Xposed or other modules. Granting an app root does not universally exempt its ordinary process from every filter.

## What it does not provide

This is a port of an independent SUSFS-compatible LKM, protocol v2.3.0. It is not canonical in-tree SUSFS and has no claim of full feature parity.

- No general SUSFS WebUI/controller is included.
- Metadata, mapping and redirect support does not mean rules for every app are configured.
- App/package lists, emulator identity, injection traces and hardware attestation are separate issues.
- Hiding rules cannot guarantee that all apps will consider the device unmodified.

Install extra controllers only after checking their compatibility with this engine. Installing a generic module cannot supply kernel hooks that this build does not implement.

## Policy tool

Installation uses the checksum-pinned standalone `magiskpolicy` utility from Magisk v27.0 to compile policy. It does not install Magisk root or its Manager. The pin is deliberate: different parser versions handle ioctl ranges differently. The compiled output hashes and the actual permissions are checked separately.

## Diagnostics and removal

```sh
python3 ksu.py verify-hardening --instance INDEX
python3 ksu.py verify-susfs --instance INDEX
```

A ready/version response verifies startup and identity, not every hiding behavior. Behavioral coverage is listed in [validation](VALIDATION.md).

To stop loading the SUSFS engine, disable **MuMu SUSFS** in KernelSU Next's Modules screen and cold-boot. Keep SELinux enforcing independently of that choice. Do not hot-unload either kernel module.
