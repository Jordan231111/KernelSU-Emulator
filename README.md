# KernelSU-Emulator

Install KernelSU Next and the MuMu SUSFS port on **MuMuPlayer Pro 1.9.2 for Apple Silicon**, with SELinux enforcing and MuMu's built-in root removed.

The installer uses MuMu's original kernel and the selected instance's private system disk. Other MuMu builds and Windows are unsupported.

## Download

Download `KernelSU-Emulator-v1.1.1-mumu-pro-1.9.2-arm64.zip` and
`SHA256SUMS-v1.1.1.txt` from the [latest release](https://github.com/Jordan231111/KernelSU-Emulator/releases/latest).
Verify the archive before extracting:

```sh
shasum -a 256 -c SHA256SUMS-v1.1.1.txt
```

The complete ZIP contains the installer, matching prebuilt `out/core/` and
`out/susfs/` bundles, corresponding source archives, and licenses. Docker is not
needed to install the release. To build your own bundles, follow [Building](docs/BUILDING.md).

Requirements:

- macOS on Apple Silicon and MuMuPlayer Pro **1.9.2**.
- Python **3.11.8 or later** and Android Platform Tools (`adb`).
- For fresh installation: `qemu-img` and `e2fsprogs` (`brew install qemu e2fsprogs`).
- Keep the MuMu launcher open. Docker is needed only to build from source.

Open Terminal in the extracted folder. Run `python3 ksu.py list` and replace `0` below with your intended instance index. Close games before commands that stop or restart an instance.

## Fresh installation

Uninstall any other root framework first. For Magisk, use its **Complete Uninstall**.

1. Install the core:

   ```sh
   python3 ksu.py install --instance 0 --bundle out/core
   ```

2. In Android, open **KernelSU Next → Superuser → Shell** and allow root for Shell.

3. Install the enforcing policy and SUSFS, then remove MuMu's root helpers:

   ```sh
   python3 ksu.py harden-existing --instance 0 --bundle out/core --susfs-bundle out/susfs
   python3 ksu.py clean-vendor-root --instance 0
   ```

4. Verify:

   ```sh
   python3 ksu.py verify --instance 0 --root
   python3 ksu.py verify-hardening --instance 0
   python3 ksu.py verify-susfs --instance 0
   python3 ksu.py verify-vendor-cleanup --instance 0
   ```

KernelSU Next should show **Working**. Test MuMu's Recent Apps button and Clear All. Grant other apps root individually.

If v1.1.0 stopped during the vendor-root check, rerun step 1 from v1.1.1. If it stopped during the offline SELinux label check, rerun step 3. The installer verifies the existing files and resumes the disk work. A healthy installation needs no runtime upgrade for v1.1.1.

Installation and maintenance modify the selected instance in place without backups or clones.

On a repeat core install, the installer checks the installed payload, init script, Manager APK, and running kernel before changing MuMu settings. An exact, healthy match returns `already_installed`. To apply a qualified compatible core update in place, use `python3 ksu.py upgrade --instance 0 --bundle out/core`, followed by `python3 ksu.py install-susfs --instance 0 --bundle out/susfs`. These validate the staged files and verify the next cold boot.

## Required settings

| Setting | Value |
| --- | --- |
| MuMu system disk mode | **Writable** |
| MuMu built-in root | **Off** after installation |
| Android `/system` mount | Read-only during normal use |
| SELinux | **Enforcing** |
| Hide SELinux modification | Your choice; saved On and Off both persist |
| AVC spoofing | **Off** by default; KernelSU's switch and the separately tested SUSFS audit hook are distinct |

MuMu's Writable setting selects the private disk containing the installation. Android's read-only `/system` mount protects that disk during normal use.

## Included components

- MuMu-compatible KernelSU Next legacy module and official **v3.4.2** Manager/daemon.
- Maintained SUSFS LKM with MuMu adaptations and the **v2.4.0** UID-filter protocol port, plus Sidex's current universal client. Defaults cover path, module-name, mount and root-Manager UID filtering.
- SELinux labels and permissions for MuMu's graphics, media, input, toolbar, and hardware services.
- Fingerprint-checked optimizer repair and vendor-root removal.
- Installer, vendor-root cleanup, and verification commands.
- Integrated MuMu Disk Cleanup compatibility, including a fixed-purpose client and confined trim service.

Zygisk, Xposed, and integrity modules are separate installations. The SUSFS port has limited coverage and cannot guarantee root hiding or hardware-backed device attestation.

## Guides

- [Architecture](docs/ARCHITECTURE.md)
- [SELinux and SUSFS](docs/SELINUX-SUSFS.md)
- [Service permissions and troubleshooting](docs/SERVICE-POLICY.md)
- [Disk Cleanup repair and qualification](docs/DISK-CLEANUP.md)
- [November 20 audit and installed revisions](docs/AUDIT-2026-11-20.md)
- [Frida compatibility and qualification](docs/FRIDA.md)
- [Building](docs/BUILDING.md)
- [Guest tests](tests/guest/README.md)
- [Porting](docs/PORTING.md)

Original installer/test code is MIT-licensed; kernel modifications are GPL-2.0-only. Bundled components retain their upstream licenses. See [NOTICE](NOTICE.md).
