# KernelSU-Emulator

Install KernelSU Next and the MuMu SUSFS port on **MuMuPlayer Pro 1.9.2 for Apple Silicon**, with SELinux enforcing and MuMu's built-in root removed.

The installer uses MuMu's original kernel and the selected instance's private system disk. Other MuMu builds and Windows are unsupported.

## Download

Download `KernelSU-Emulator-v1.0.5-mumu-pro-1.9.2-arm64.zip` and `SHA256SUMS-v1.0.5.txt` from the [latest release](https://github.com/Jordan231111/KernelSU-Emulator/releases/latest).

The ZIP contains the installer, matched `core/` and `susfs/` bundles, source archives, and licenses. Verify it before extracting:

```sh
shasum -a 256 -c SHA256SUMS-v1.0.5.txt
```

Requirements:

- macOS on Apple Silicon and MuMuPlayer Pro **1.9.2**.
- Python **3.11.8 or later** and Android Platform Tools (`adb`).
- For fresh installation: `qemu-img` and `e2fsprogs` (`brew install qemu e2fsprogs`).
- Keep the MuMu launcher open. Docker is needed only to build from source.

Open Terminal in the extracted folder. Run `python3 ksu.py list` and replace `0` below with your intended instance index. Close games before commands that stop or restart an instance.

## Update an existing installation

Apply the current SELinux and service repairs, including the Recent Apps toolbar fix:

```sh
python3 ksu.py update-policy --instance 0
python3 ksu.py stop --instance 0
python3 ksu.py start --instance 0
python3 ksu.py verify-hardening --instance 0
```

This preserves KernelSU, SUSFS, apps, and launcher settings. It requires authorized Shell root and a recognized policy installation. See [Updating](docs/UPDATING.md) for core or SUSFS updates.

## Fresh installation

Uninstall any other root framework first. For Magisk, use its **Complete Uninstall**.

1. Install the core:

   ```sh
   python3 ksu.py install --instance 0 --bundle core
   ```

2. In Android, open **KernelSU Next → Superuser → Shell** and allow root for Shell.

3. Install the enforcing policy and SUSFS, then remove MuMu's root helpers:

   ```sh
   python3 ksu.py harden-existing --instance 0 --bundle core --susfs-bundle susfs
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

Installation and maintenance modify the selected instance in place without backups or clones.

## Required settings

| Setting | Value |
| --- | --- |
| MuMu system disk mode | **Writable** |
| MuMu built-in root | **Off** after installation |
| Android `/system` mount | Read-only during normal use |
| SELinux | **Enforcing** |
| Hide SELinux modification | Your choice; saved On and Off both persist |
| AVC spoofing | **Off**; this port does not connect its audit hook |

MuMu's Writable setting selects the private disk containing the installation. Android's read-only `/system` mount protects that disk during normal use.

## Included components

- MuMu-compatible KernelSU Next legacy module and official **v3.4.2** Manager/daemon.
- SUSFS-compatible LKM, protocol **v2.3.0**, with default path, module-name, and mount filtering.
- SELinux labels and permissions for MuMu's graphics, media, input, toolbar, and hardware services.
- Fingerprint-checked optimizer repair and vendor-root removal.
- Installer, policy migration, framework update, and verification commands.

Zygisk, Xposed, and integrity modules are separate installations. The SUSFS port has limited coverage and cannot guarantee root hiding or hardware-backed device attestation.

## Guides

- [Architecture](docs/ARCHITECTURE.md)
- [SELinux and SUSFS](docs/SELINUX-SUSFS.md)
- [Updating](docs/UPDATING.md)
- [Service permissions and troubleshooting](docs/SERVICE-POLICY.md)
- [Building](docs/BUILDING.md)
- [Guest tests](tests/guest/README.md)
- [Porting](docs/PORTING.md)

Original installer/test code is MIT-licensed; kernel modifications are GPL-2.0-only. Bundled components retain their upstream licenses. See [NOTICE](NOTICE.md).
