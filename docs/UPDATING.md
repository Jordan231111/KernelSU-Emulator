# Updating

Use the [latest complete release](https://github.com/Jordan231111/KernelSU-Emulator/releases/latest). Keep MuMu's system disk **Writable**, its built-in root **Off**, and Shell authorized in KernelSU Next. Close games before restarting an instance.

Run `python3 ksu.py list` and replace `0` below with your intended instance index.

## Policy and service repairs

Run these commands from the extracted release:

```sh
python3 ksu.py update-policy --instance 0
python3 ksu.py stop --instance 0
python3 ksu.py start --instance 0
python3 ksu.py verify-hardening --instance 0
```

This applies the current service permissions, labels, and Recent Apps repair to a recognized installation. It preserves apps, root grants, and the saved SELinux-hiding preference. Unknown or modified policy inputs are rejected.

`update-policy` does not replace the KernelSU core startup files or SUSFS module.

## Core payload

When replacing the core, supply the bundle matching the installed payload and the new release's `core` directory:

```sh
python3 ksu.py upgrade --instance 0 \
  --from-bundle /path/to/installed-release/core --bundle core
python3 ksu.py update-policy --instance 0
python3 ksu.py stop --instance 0
python3 ksu.py start --instance 0
```

The old bundle identifies the installed software; it is not a device backup. If it is unavailable, build it from the matching Git tag using [Building](BUILDING.md). Do not substitute an unrelated bundle or update Manager independently of its paired kernel/daemon.

## SUSFS module

Install the matched module from the current release:

```sh
python3 ksu.py install-susfs --instance 0 --bundle susfs
```

The command performs a cold boot. To disable SUSFS, disable **MuMu SUSFS** in Next's Modules screen and cold-boot. Keep SELinux enforcement enabled. Do not hot-unload either kernel module.

## Verification

```sh
python3 ksu.py verify --instance 0 --root
python3 ksu.py verify-hardening --instance 0
python3 ksu.py verify-susfs --instance 0
python3 ksu.py verify-vendor-cleanup --instance 0
```

Test Recent Apps and Clear All, native mouse/keyboard input, and the apps you use. A successful process-state check alone does not test every hardware function.

All changes are made in place. No disk backup, clone, or rollback is created. Remove downloaded bundles and local build output when no longer needed.

## Maintaining compatibility profiles

Profiles pin MuMu, the kernel, driver, upstream sources, userspace binaries, and repair files. New upstream versions are selected manually and tested in a separate lab instance.

### MuMu updates

1. Capture the target with `capture --instance INDEX --output /path/to/capture.json --root` and compare it with `compare /path/to/capture.json`.
2. If kernel and driver fingerprints are unchanged, `new-profile --capture /path/to/capture.json --base mumu-pro-1.9.2-arm64 --id PROFILE_ID` prepares a candidate. Changed system files still require policy and cleanup review.
3. For a changed kernel or driver, follow [Porting](PORTING.md). Recheck structure layouts, symbols, and module loading before using the current patches.
4. Build the candidate and test installation, upgrade, root authorization, service behavior, enforcement, and cold boots in a registered lab.

### KernelSU Next updates

`updates` lists upstream revisions without installing them. `prepare-framework --base mumu-pro-1.9.2-arm64 --id PROFILE_ID --kernel-ref COMMIT --manager-tag TAG` prepares an explicitly selected candidate.

Review credentials, hooks, policy changes, Manager authentication, daemon protocol, and module lifecycle. Rebase patches without dropping required fixes. Check the control protocol in `native/ksu_probe.c`, then build and qualify the paired bundle. A different root fork requires a clean lab and its own kernel/userspace contract.

### SUSFS updates

Update the candidate's `susfs.json`: pin the source commit and archive hash, module version, protocol, and patches. Build for MuMu's kernel; generic GKI binaries are incompatible. Preserve namespace locking, path filtering, and the kernel API adaptations when rebasing.

Test path, mount, metadata, and mapping behavior from unprivileged processes, plus module disable/re-enable and cold boots. See [guest tests](../tests/guest/README.md).

### SELinux and vendor-service updates

1. Inspect the target's original policy, init files, contexts, service identities, and hardware dependencies. Keep proprietary inputs out of Git.
2. Create exact-input/exact-output patches. Match denials to real failures instead of granting every denied operation.
3. Compile with the pinned policy utility. Inspect permissions, ioctl ranges, type attributes, and app isolation with SETools before accepting output hashes.
4. Add previous recipe, policy, file, label, helper, and boot-file fingerprints to `policy-migrations.json`. Test rejection of altered inputs and a real migration, including cleanup and the read-only remount.
5. Recheck `binary_repairs` and `vendor-cleanup.json` against the actual helper binaries and companion APK. Preserve normal emulator integration when removing vendor root.
6. Run native-input, toolbar, media, app-isolation, service-lifecycle, and cold-boot checks. Use a full emulator restart for central bridge changes.

A candidate can become verified only after its affected features pass [guest qualification](../tests/guest/README.md). Rebuild the final bundles after changing profile contents. Publish the complete installer, matched payloads, corresponding sources, licenses, and checksums together.
