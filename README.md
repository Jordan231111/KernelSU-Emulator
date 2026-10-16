# KernelSU-Emulator

Install **KernelSU Next and the MuMu SUSFS port** on **MuMuPlayer Pro 1.9.2 for Apple Silicon**, with SELinux enforcing and MuMu's built-in root removed.

The installer keeps MuMu's original kernel. It loads compatible KernelSU and SUSFS kernel modules from the selected instance's private system disk. Other MuMu builds and Windows are not supported by this profile.

## Download

Download the ZIP and checksum file from the [latest release](https://github.com/Jordan231111/KernelSU-Emulator/releases/latest). Extract the ZIP, then open Terminal in the extracted folder. It contains `ksu.py`, its supporting files, and the matched `core/` and `susfs/` payloads.

Requirements:

- macOS on Apple Silicon, MuMuPlayer Pro **1.9.2**.
- Python **3.11.8 or later** and Android Platform Tools (`adb`).
- `qemu-img` and `e2fsprogs`: `brew install qemu e2fsprogs`.
- Keep the MuMu launcher open. Docker is needed only to build from source.

Optional download verification, before extracting:

```sh
shasum -a 256 -c SHA256SUMS-v1.0.4.txt
```

## Repair an existing v1.0.1 or v1.0.2 installation

Use the new release's `ksu.py`. This applies the SELinux and vendor-service repairs without reinstalling KernelSU, SUSFS or your apps:

```sh
python3 ksu.py list
python3 ksu.py update-policy --instance 0
python3 ksu.py stop --instance 0
python3 ksu.py start --instance 0
python3 ksu.py verify-hardening --instance 0
```

**Replace `0` with the index shown for your intended device.** Close games before stopping an instance. This repair needs Python, ADB and MuMu; the disk tools are needed for fresh installation. Unknown or modified policy installations are rejected instead of overwritten.

## Install on an instance without KernelSU

If Magisk is installed, use its **Complete Uninstall** first. Do not install over another root framework.

1. List instances and install the core on the intended index:

   ```sh
   python3 ksu.py list
   python3 ksu.py install --instance 0 --bundle core
   ```

2. In Android, open **KernelSU Next → Superuser → Shell** and allow root for Shell.

3. Install the enforcing policy and SUSFS, then remove MuMu's old root helpers:

   ```sh
   python3 ksu.py harden-existing --instance 0 --bundle core --susfs-bundle susfs
   python3 ksu.py clean-vendor-root --instance 0
   ```

4. Check the installation:

   ```sh
   python3 ksu.py verify --instance 0 --root
   python3 ksu.py verify-hardening --instance 0
   python3 ksu.py verify-susfs --instance 0
   python3 ksu.py verify-vendor-cleanup --instance 0
   ```

KernelSU Next should show **Working**. Grant root to other apps individually. The tools modify the selected instance in place and do not create backups or clones.

## Settings to keep

| Setting | Use |
| --- | --- |
| MuMu system disk mode | **Writable**; this selects the modified private disk |
| MuMu built-in root | **Off** after installation |
| Android `/system` mount | Normally read-only; KernelSU still works |
| SELinux mode | **Enforcing** after hardening |
| Hide SELinux modification | Your choice; saved On and Off both persist |
| AVC spoofing | Off in this port; its Next audit hook is not connected |

Changing MuMu's disk mode to Readonly bypasses the private disk containing the installation. It is different from mounting Android's `/system` read-only.

## What is included

- A MuMu-compatible KernelSU Next legacy kernel port with the official **v3.4.2** Manager and daemon.
- A separate **SUSFS-compatible LKM**, protocol v2.3.0, with baseline path, module-name and mount-hiding configuration.
- SELinux service identities, file labels and virtual-hardware permissions for this MuMu build.
- A checksum-locked fix for the MuMu optimizer's restart handling.
- Installation, policy repair, framework updates and vendor-root cleanup commands.
- Startup logs retained up to 64 KiB each, trimmed during startup and boot completion without a background watcher or archived copies.

The SUSFS port is not the complete canonical SUSFS implementation or a universal root-hiding guarantee. Zygisk, Xposed and integrity modules are separate installations. MuMu remains an emulator; this project does not provide hardware-backed device attestation.

## Guides

- [How the installation works](docs/ARCHITECTURE.md)
- [SELinux and SUSFS settings](docs/SELINUX-SUSFS.md)
- [Updating MuMu, KernelSU Next or SUSFS](docs/UPDATING.md)
- [Service permissions and troubleshooting](docs/SERVICE-POLICY.md)
- [Building from source](docs/BUILDING.md)

Developer material is separate: [test results](docs/VALIDATION.md), [guest regression tests](tests/guest/README.md), [porting notes](docs/PORTING.md), and [framework research](research/ROOT-FRAMEWORKS.md).

Original installer/test code is MIT-licensed; kernel modifications are GPL-2.0-only. Upstream licenses apply to bundled components. MuMu's proprietary kernel and disks are not distributed. See [NOTICE](NOTICE.md).
