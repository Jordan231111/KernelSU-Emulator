# KernelSU-Emulator

**KernelSU Next + SUSFS with genuine SELinux enforcing on MuMuPlayer Pro 1.9.2 for Apple Silicon.** Includes matched kernel ports, an in-place installer/updater, vendor-root removal and qualification tools.

MuMu keeps its working vendor kernel and virtual hardware. The selected instance's private Android system disk stores KernelSU's module and boot instructions. A second kernel module provides SUSFS. The enforcing configuration repairs MuMu's labels, service identities and driver policy.

Read [how everything works](docs/ARCHITECTURE.md), the [framework comparison](research/ROOT-FRAMEWORKS.md), [SELinux/SUSFS details](docs/SELINUX-SUSFS.md), and [validation evidence](docs/VALIDATION.md).

## Supported target

| Component | Qualified configuration |
| --- | --- |
| Host | macOS, Apple Silicon |
| Emulator / Android | MuMuPlayer Pro **1.9.2**, Android 12 ARM64 |
| Kernel | `4.19.195-android-arm64-gedae1315d023` |
| Root | Custom Next legacy port; official v3.4.2 Manager/daemon, 33355 / UAPI 5 |
| SUSFS | Independent LKM, protocol v2.3.0, ported to MuMu 4.19 |
| SELinux | Actual enforcing after `harden-existing`; ordinary app isolation tested |

Exact app/kernel/configuration/driver fingerprints and sources are pinned. Other versions need a candidate profile and qualification. Universal root invisibility and hardware-backed Play Integrity certification are not claimed. Windows MuMu installation is not implemented.

## Install

Requirements: Python **3.11.8+**, Android Platform Tools (`adb`), MuMuPlayer Pro, `qemu-img` and `e2fsprogs` (`brew install qemu e2fsprogs`). Keep the MuMu launcher open. Docker is needed to build; prebuilt installation can use native filesystem tools.

Use the repository tag matching your [release bundle](https://github.com/Jordan231111/KernelSU-Emulator/releases). Extract its `core/` and `susfs/` directories into `out/releases/v1.0.2/`, or build them:

```sh
python3 ksu.py build --output out/releases/v1.0.2/core
python3 ksu.py build-susfs --output out/releases/v1.0.2/susfs
python3 ksu.py list
```

Select the exact instance by index and name. **2 below is an example; substitute your index.** Remove an existing Magisk installation through its own Complete Uninstall first, then confirm its modules and startup services are gone. Do not layer this over another root framework. If you want a fresh development instance, `create-lab --name 'KernelSU Lab'` creates an empty instance; it copies no existing instance.

```sh
python3 ksu.py install --instance 2 --bundle out/releases/v1.0.2/core
```

Open **KernelSU Next → Superuser → Shell** and enable root for Shell. Then apply enforcement and SUSFS to the **same instance**:

```sh
python3 ksu.py verify --instance 2 --root
python3 ksu.py harden-existing --instance 2 \
  --bundle out/releases/v1.0.2/core \
  --susfs-bundle out/releases/v1.0.2/susfs
python3 ksu.py clean-vendor-root --instance 2
python3 ksu.py verify --instance 2 --root
python3 ksu.py verify-hardening --instance 2
python3 ksu.py verify-susfs --instance 2
python3 ksu.py verify-vendor-cleanup --instance 2
```

The cleanup removes fingerprinted vendor su/console helpers and their startup code from the private disk. It disables the vendor companion's obsolete su-dependent boot receiver and starts its ordinary emulator API service through the checked KernelSU boot helper. It preserves the emulator's graphics/input services and user applications. Unknown helper binaries or another installed framework are rejected for review.

Manager should show **Working**, Next v3.4.2 and **SuSFS Supported | v2.3.0 (NON-GKI)**. `LKM (GKI1)`, `Custom`, `Manual` and `Jailbreak mode` describe the integration. Grant root to each other app individually.

Core-only `install` preserves MuMu's original SELinux mode. `harden-existing` adds enforcement; omit `--susfs-bundle` to omit SUSFS. A matching SUSFS update uses `install-susfs --instance INDEX --bundle PATH`.

## SELinux hiding is your choice

**Hide SELinux modification defaults to On** when no preference is saved. Change it in KernelSU Next's Settings; both On and Off persist through cold boots. The boot scripts no longer override that switch. Existing saved preferences are preserved during upgrades.

SELinux itself remains genuinely enforcing with either choice. Verification reads the real kernel flag as root and tests actual access denials; an app-facing status display is not used as proof. AVC spoofing remains disabled because its audit hook is not connected in this port.

For an existing v1.0.1 installation, use the v1.0.2 repository and its new core bundle with `upgrade --from-bundle out/releases/v1.0.1/core --bundle out/releases/v1.0.2/core --instance INDEX`. The updater verifies and migrates the exact previous hardening boot script while preserving the SELinux policy and your saved preference. No SUSFS reinstall is needed.

## MuMu Writable versus Android read-only

Keep **MuMu's system-disk setting on Writable**. On the tested version, switching it to Readonly selects a different system view and bypasses the modified private disk; it is not simply write-protecting the installed files. A marker-file test confirmed this behavior.

Inside Android, `/system` normally mounts **read-only** after vendor cleanup. KernelSU and SUSFS work with that mount. Maintenance temporarily writes the selected disk; cold boot returns it to the normal read-only mount.

## Updates and storage

Follow [the update guide](docs/UPDATING.md) for new MuMu, Next, SUSFS, policy or fork versions. For a framework-only update, authorize Shell and provide the installed and new matching bundles:

```sh
python3 ksu.py upgrade --instance 2 \
  --from-bundle out/releases/OLD/core \
  --bundle out/releases/NEW/core
```

This updates the selected instance directly. It verifies the installed files and Manager against the old bundle, checks the new bundle, and tests two cold boots. The existing SELinux recipe must remain compatible. The reviewed v1.0.1 startup-only migration is supported; a changed policy recipe requires its own reviewed migration; it is not applied blindly over an older repair.

**No backup disks, recovery copies, saved original system files or automatic instance clones are created.** The former `restore`, `clone-lab`, `upgrade-clone` and `enhance-clone` workflows are removed. Disk rewrites use temporary working files and atomic replacement; normal completion and handled failures remove those files. Small JSON reports contain checksums/results, not recoverable disk contents. Power loss or unreachable Android can leave temporary staging files; inspect and remove those only while the instance is stopped.

Installation failures stop the selected instance and report the failed check. They do not restore old disk contents. Boot guards can skip a failed SUSFS load or fall back from failed enforcement; these guards store small boot markers, not backups. Verification never reports a permissive fallback as successful enforcement. Disable SUSFS in Next's Modules screen and cold-boot to remove its running engine. **Do not use `rmmod`** on these pinned kernel modules.

## Development and licensing

```sh
python3 ksu.py profiles
python3 ksu.py capture --instance 2 --root --output out/captures/current
python3 ksu.py updates
python3 -m unittest discover -s tests -v
```

[Guest tests](tests/guest/README.md) exercise root authorization, app functionality, enforcement, filesystem observations and concurrency. CI does not replace emulator testing. Use `--app '/path/MuMuPlayer Pro.app'` and `--adb /path/to/adb` before a subcommand to override tool locations. Builds, disks and local diagnostic captures are ignored by Git.

Original orchestration/test code is MIT-licensed; kernel modifications are GPL-2.0-only. Upstream licenses remain applicable. Corresponding source archives accompany release binaries. MuMu's proprietary kernel, driver and VM disks are not redistributed. See [NOTICE](NOTICE.md) and [patch licensing](patches/README.md).
