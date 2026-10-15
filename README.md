# KernelSU-Emulator

**KernelSU Next + SUSFS with genuine SELinux enforcing on MuMuPlayer Pro 1.9.2 for Apple Silicon.** The repository contains the matched kernel ports, installer, clone upgrades, recovery, and repeatable qualification tools.

MuMu keeps its vendor kernel and virtual hardware. The selected instance's private Android system disk stores the root module and boot instructions. A second, separately built kernel module supplies SUSFS through KernelSU's standard module lifecycle. The enforcing configuration repairs MuMu's labels, service identities and driver policy.

Read [how everything works](docs/ARCHITECTURE.md), the [framework comparison](research/ROOT-FRAMEWORKS.md), [SELinux and SUSFS details](docs/SELINUX-SUSFS.md), and [validation evidence](docs/VALIDATION.md).

## Supported target

| Component | Qualified configuration |
| --- | --- |
| Host | macOS, Apple Silicon |
| Emulator / Android | MuMuPlayer Pro **1.9.2**, Android 12 ARM64 |
| Kernel | `4.19.195-android-arm64-gedae1315d023` |
| Root | Custom KernelSU Next legacy port; official v3.4.2 Manager/daemon, 33355 / UAPI 5 |
| SUSFS | Independent LKM implementation, protocol v2.3.0, specifically ported to MuMu 4.19 |
| SELinux | Actual enforcing after the optional full enhancement; ordinary app isolation tested |

Exact app/kernel/configuration/driver fingerprints and source revisions are pinned. Other MuMu versions require a candidate profile and qualification. This does not promise universal root invisibility or hardware-backed Play Integrity certification. Windows MuMu installation is not implemented.

## Install the complete configuration

Requirements: Python **3.11.8+**, Android Platform Tools (`adb`), `qemu-img`, MuMuPlayer Pro, and `e2fsprogs` for the offline label repair (`brew install qemu e2fsprogs`). Keep the MuMu launcher open. Docker is needed to build; a prebuilt installation can use native e2fsprogs without Docker.

Clone this repository at the release tag corresponding to your bundle. Obtain the complete bundle from [Releases](https://github.com/Jordan231111/KernelSU-Emulator/releases), and extract its `core/` and `susfs/` directories into `out/releases/v1.0.0/`. Keep old release bundles in their own directories.

Alternatively, build both components from pinned sources:

```sh
python3 ksu.py build --output out/releases/v1.0.0/core
python3 ksu.py build-susfs --output out/releases/v1.0.0/susfs
```

Create a clean base instance:

```sh
python3 ksu.py list
python3 ksu.py create-lab --name 'KernelSU Base'
```

Use the returned index; **2 below is only an example**:

```sh
python3 ksu.py install --instance 2 --bundle out/releases/v1.0.0/core
```

Open **KernelSU Next → Superuser → Shell** and enable its root permission. This is required for the host to perform subsequent maintenance through authorized KernelSU root. Then:

```sh
python3 ksu.py verify --instance 2 --root
python3 ksu.py enhance-clone --instance 2 \
  --from-bundle out/releases/v1.0.0/core \
  --bundle out/releases/v1.0.0/core \
  --susfs-bundle out/releases/v1.0.0/susfs \
  --name 'KernelSU Next + SUSFS Enforcing'
```

Use the **new enhanced instance** printed by the command. The complete original remains your recovery copy. Verify the new index, for example 3:

```sh
python3 ksu.py verify --instance 3 --root
python3 ksu.py verify-hardening --instance 3
python3 ksu.py verify-susfs --instance 3
```

Manager should show **Working**, Next v3.4.2, and **SuSFS Supported | v2.3.0 (NON-GKI)**. `LKM (GKI1)`, `Custom`, `Manual`, and `Jailbreak mode` describe this port's integration; they do not mean a generic GKI image was installed. Grant other apps root individually in Manager.

The core-only `install` command preserves MuMu's original SELinux mode. `enhance-clone` installs the enforcing repairs. Omit `--susfs-bundle` for an enforcing root clone without SUSFS. A separately installed matching SUSFS bundle uses `install-susfs --instance INDEX --bundle PATH`.

## Updating an existing installation

Follow [the update guide](docs/UPDATING.md). It covers a new MuMu app with the same kernel, a changed kernel, new Next releases, SUSFS updates, policy updates and a different root fork.

For a framework-only update, authorize Shell and retain both complete bundles:

```sh
python3 ksu.py upgrade-clone --instance 3 \
  --from-bundle out/releases/OLD/core \
  --bundle out/releases/NEW/core
```

Use `enhance-clone` to add enforcement to a core-only instance. It deliberately rejects an already hardened instance; policy migrations require a reviewed migration or a new clone from a core-only base. Manager's generic boot-image/kernel update buttons are not the update procedure for MuMu's custom layout.

No command automatically trusts or installs a moving upstream branch. Candidates require `--experimental` and are tested in registered clones.

## Recovery

For an enhancement or upgrade, select the preserved original instance. This restores the complete environment, including Android userdata; a system-only backup cannot undo an APK/database migration.

The initial core installer also prints a recovery receipt:

```sh
python3 ksu.py restore out/backups/INSTANCE-DIRECTORY/receipt.json
```

That restores the selected instance's original system disk/settings and removes the Manager installed by the tool. It retains `/data/adb` module data and logs; it is not a full userdata backup. Keep the receipt and its checksummed backup files.

SUSFS can be disabled or removed in Next's Modules screen, followed by a full stop/start. Both kernel modules are pinned in memory: **do not use `rmmod`**. A failed SUSFS startup is skipped on the following boot; a failed enforcing boot falls back to the previous permissive mode. Verification reports that fallback as failure. See [recovery details](docs/SELINUX-SUSFS.md#recovery).

## Development and licensing

```sh
python3 ksu.py profiles
python3 ksu.py capture --instance 3 --root --output out/captures/current
python3 ksu.py updates
python3 -m unittest discover -s tests -v
```

[Guest tests](tests/guest/README.md) exercise actual root behavior, app functionality, enforcement, filesystem observations and concurrency. CI does not replace emulator testing.

Use `--app '/path/MuMuPlayer Pro.app'` and `--adb /path/to/adb` before the subcommand to override tool locations. Local experiments, builds, VM disks, receipts and captures are ignored by Git.

Original orchestration and test code is MIT-licensed. Kernel modifications are GPL-2.0-only; upstream components retain their licenses. Full corresponding source archives accompany the release binaries. MuMu's kernel, proprietary driver and VM disks are not redistributed. See [NOTICE](NOTICE.md) and [patch licensing](patches/README.md).
