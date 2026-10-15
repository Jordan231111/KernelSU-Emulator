# KernelSU-Emulator

Install **KernelSU Next 3.4.2 on MuMuPlayer Pro 1.9.2 for Apple Silicon**, using a custom loadable module that matches MuMu's kernel ABI.

The stock MuMu kernel and application bundle stay intact. The installer adds a verified module, daemon, and Android init action to the selected instance's private system disk. KernelSU loads on every cold boot. MuMu's vendor root is disabled after installation, so KernelSU Manager controls root grants.

## Tested target

| Component | Verified configuration |
| --- | --- |
| Host | macOS, Apple Silicon |
| Emulator | MuMuPlayer Pro 1.9.2 |
| Android | 12, ARM64 |
| Kernel | `4.19.195-android-arm64-gedae1315d023` |
| Kernel build | `#1 SMP PREEMPT Thu Sep 10 15:06:08 CST 2026` |
| KernelSU | Next legacy branch, custom port compatible with v3.4.2 / 33355 / UAPI 5 |

The installer checks the app version, kernel image hash, running kernel identity, and configuration hash. Other builds require a new verified profile. This is a tested kernel port, not a universal emulator rooter.

See [research and patch rationale](research/MUMU.md), [validation results](docs/VALIDATION.md), and [porting another kernel](docs/PORTING.md).

## Build and install

Requirements: Python **3.11.8+**, Docker with a running engine, Android Platform Tools (`adb`), `qemu-img`, and MuMuPlayer Pro. Keep the MuMu launcher open. Docker is used for building; installation uses MuMu's command-line tool and ADB.

```sh
git clone https://github.com/Jordan231111/KernelSU-Emulator.git
cd KernelSU-Emulator
python3 ksu.py build
python3 ksu.py list
python3 ksu.py create-lab --name KernelSU
```

Use the **index returned by `create-lab`** in the following commands; `2` is an example:

```sh
python3 ksu.py install --instance 2
python3 ksu.py verify --instance 2
```

The build fetches checksum-pinned sources and the official matching manager, applies the included patches, and produces `out/mumu-pro-1.9.2-arm64/`. Corresponding source archives and the build recipe accompany the binaries in its `sources/` directory. It does not download or redistribute MuMu's disks or kernel.

Installation stops only the selected instance, backs up its existing private system disk, enables a private writable system and bootstrap root, installs the payload, and verifies a cold boot. It then disables vendor root and verifies another cold boot. An installation failure attempts to restore the system disk and original settings automatically. Existing Magisk or KernelSU installations are rejected; use a clean instance.

Open **KernelSU Next** inside the emulator to grant root to individual apps. To use ADB root, open **Superuser → Shell** and enable its superuser permission. Then:

```sh
python3 ksu.py verify --instance 2 --root
```

`--keep-vendor-root` is available for development. The normal installation disables it. Manager boot-image installation and kernel updates are not supported on this custom layout. Use a fresh instance for a new profile/build; in-place upgrades are not implemented.

## Recovery

The installer prints the exact path of its recovery receipt. Keep that directory: it contains the checksum-verified, self-contained system disk backup when a private disk existed before installation.

```sh
python3 ksu.py restore out/backups/INSTANCE-DIRECTORY/receipt.json
```

Recovery stops the selected instance, restores its system disk and root/writability settings, and removes the manager APK installed by this tool. It preserves `/data/adb` module data and logs. It does not restore all Android userdata or erase unrelated apps. Recovery rejects a changed instance identity or damaged backup.

The module is deliberately pinned in memory because the legacy LSM hooks cannot be safely unloaded. **Use recovery and a cold boot**, rather than `rmmod` or Manager's module-unload action.

## Inspection and development

```sh
python3 ksu.py probe --instance 2
python3 ksu.py probe --serial emulator-5556
python3 ksu.py check-bundle out/mumu-pro-1.9.2-arm64
python3 ksu.py inspect-module out/mumu-pro-1.9.2-arm64/kernelsu.ko
python3 -m unittest discover -s tests -v
```

`probe` is read-only and can inspect other emulators. Installation currently supports the exact MuMu macOS profile above. Windows MuMu and Android Studio installation adapters are not implemented.

Use `--app '/path/MuMuPlayer Pro.app'` and `--adb /path/to/adb` before the subcommand to override tool locations. Source archives and experimental files live in ignored `.work/`; outputs, private recovery receipts, and disks live in ignored `out/`.

## Licensing

Original orchestration and verification code is MIT-licensed. Kernel patches and the resulting kernel module are GPL-2.0-only; KernelSU Next userspace and Manager retain their upstream licenses. See [NOTICE](NOTICE.md) and [patch licensing](patches/README.md). The pinned source URLs, configuration, patches, and build commands are included so the module can be rebuilt.
