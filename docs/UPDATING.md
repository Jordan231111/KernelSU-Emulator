# Updating MuMu, KernelSU Next and SUSFS

The update unit is a **compatibility profile plus its complete bundle**: kernel module, official Manager, daemon, startup scripts and source archives. Keep those together. An APK update by itself is not the update procedure for this custom port.

The tools distinguish `verified` profiles from `candidate` profiles. A candidate can be built and inspected normally, but installation requires `--experimental` and an instance registered by `create-lab`. This flag permits testing; it does not certify the result. No command automatically installs the latest GitHub commit or promotes a profile.

## Routine policy repair

For an existing v1.0.1 or v1.0.2 installation, extract the v1.0.3 release ZIP and run its script from that folder:

```sh
python3 ksu.py list
python3 ksu.py update-policy --instance 0
python3 ksu.py stop --instance 0
python3 ksu.py start --instance 0
python3 ksu.py verify-hardening --instance 0
```

Use the intended instance index and close apps before stopping it. This changes the policy, reviewed boot checks and the fingerprinted MuMu optimizer restart fix; KernelSU/SUSFS binaries, app data and saved hiding preferences remain intact. No old/new root bundle is needed for this compatibility repair. The full `upgrade` command also applies supported policy migrations automatically.

The sections below are for framework or MuMu-version updates. A new upstream release is a compatibility-review task until a matching profile and bundle are qualified.

## Before a framework or MuMu update

Updates act on the explicitly selected instance and create no backup, original-file archive or clone. A failed update is reported and the instance is stopped; old contents are not restored. Temporary disk conversion/staging files are removed on completion or a handled failure. The boot guards store only small status markers.

1. Obtain the release bundle matching the installed files and the proposed new bundle. These are software distribution artifacts, not copies of your Android data. The updater compares installed hashes with `--from-bundle` before replacing them. Downloads can be deleted after maintenance and fetched again when needed.
2. Identify the instance by index and name with `python3 ksu.py list`. Examples use **4 for the existing instance** and **6 for an optional fresh test instance**; use your actual indexes.
3. Verify root, enforcement, SUSFS and cleanup before changing anything:

```sh
python3 ksu.py verify --instance 4 --root
python3 ksu.py verify-hardening --instance 4
python3 ksu.py verify-susfs --instance 4
python3 ksu.py verify-vendor-cleanup --instance 4
python3 ksu.py capture --instance 4 --root --output out/captures/before-update
```

`capture` records compatibility evidence: kernel config, vendor reference module, symbol names and hashes. It does not copy the VM disks or Android userdata. Delete local captures after extracting the profile evidence you need.

For unqualified kernel work, an optional **fresh empty lab** can be made with `create-lab`. This creates no copy of an existing instance. Delete the lab through MuMu when finished. Candidate initial installation and SUSFS installation require a registered fresh lab; candidate in-place core updates/hardening/vendor cleanup require explicit `--experimental`.

A MuMu app update changes shared boot resources used by all instances. A private writable disk can retain the older Android system after the app update. Testing that retained system is different from testing the new app's fresh system image. Keep MuMu's GUI disk mode **Writable**; Android's actual `/system` mount can remain read-only.

## Which update path applies?

After installing the MuMu version you want to investigate, capture the test instance again:

```sh
python3 ksu.py capture --instance 4 --root --output out/captures/new-mumu
python3 ksu.py compare out/captures/new-mumu
```

| Result | Meaning | Next action |
| --- | --- | --- |
| `identical-tested-target` | The compared app, kernel and driver identities match | Use the current verified profile; this is not a new kernel port |
| `app-update-same-kernel` | App/Android metadata changed while the compared kernel and driver fingerprints matched | Prepare a candidate; still test startup, driver behavior and the installer |
| `kernel-port-required` | Kernel identity, configuration or vendor driver changed | Follow the manual kernel-port procedure below |
| `insufficient-evidence` | The vendor reference module could not be verified | Obtain that evidence first; reuse is refused |

A matching `uname -r` alone never authorizes reuse. If the new app cannot boot the old installation, make a **fresh lab instance** in that app version, capture it, and use the manual path. Do not keep injecting the old module into an unknown kernel.

## A. New MuMu version, unchanged kernel and vendor module

Choose a descriptive, unused ID containing lowercase letters, digits, dots, underscores or hyphens. Here `mumu-new-arm64` is an example, not an existing supported version:

```sh
python3 ksu.py new-profile --base mumu-pro-1.9.2-arm64 \
  --capture out/captures/new-mumu --id mumu-new-arm64
python3 ksu.py preflight --profile mumu-new-arm64
python3 ksu.py build --profile mumu-new-arm64
python3 ksu.py check-bundle out/mumu-new-arm64
```

This copies the reviewed build recipe and captures the new target identity as a **candidate**. It refuses to invent structure padding for a changed kernel. Patch preflight uses pinned source archives in a temporary directory, rejects fuzzy patch application and applies sequential patches there so dependent patches can be checked.

To update the selected installation in place:

```sh
python3 ksu.py upgrade --instance 4 \
  --from-bundle out/releases/OLD/core \
  --bundle out/mumu-new-arm64 --experimental
```

Authorize Shell in Manager first. The command checks every installed payload file and Manager APK against `--from-bundle`, stages and validates the new files, updates the same-package Manager, publishes the startup entry and tests two cold boots with vendor root off. Android rejects a different signing identity. Existing enforcing installations must pass the core-service health checks after each boot. Known policy migrations run automatically; unknown recipes are rejected.

A failure stops that instance and records the failed check. There is no rollback or retained original instance. Inspect the record and correct the measured cause before booting the same changed configuration again.

For a clean installation instead:

```sh
python3 ksu.py create-lab --name 'KernelSU Candidate Clean Install'
python3 ksu.py install --instance 6 --bundle out/mumu-new-arm64 --experimental
```

## B. New KernelSU Next release or legacy-branch revision

First inspect what changed:

```sh
python3 ksu.py updates --profile mumu-pro-1.9.2-arm64
```

This checks the configured framework repository's kernel branch and latest stable Manager release, plus the configured SUSFS source branch when present. It reports differences and installs nothing. It does not claim to find or approve the latest MuMu build.

Select the exact kernel branch/commit and Manager tag intentionally. The following example reselects the currently tested revisions to illustrate the complete workflow; replace the tag/ref when reviewing a real new release:

```sh
python3 ksu.py prepare-framework --base mumu-pro-1.9.2-arm64 \
  --id mumu-next-candidate --kernel-ref legacy --manager-tag v3.4.2
python3 ksu.py preflight --profile mumu-next-candidate
python3 ksu.py build --profile mumu-next-candidate
```

The preparation command resolves refs to immutable commits, records archive/APK SHA-256 hashes, extracts and hashes the matching ARM64 daemon, and reads the kernel control-API version. If a release has multiple eligible APKs, select the exact official filename with `--manager-asset`. Public GitHub API limits can be increased with your usual `GH_TOKEN` or `GITHUB_TOKEN` environment variable; tokens are not written into profiles.

**Review before installation:**

1. Read the upstream changes between the pinned and proposed commits, particularly credentials, syscall/LSM hooks, SELinux policy, manager authentication, daemon protocol and module lifecycle.
2. Confirm the APK's package/version/signing certificate and the kernel's expected Manager authentication values. Android SDK `apksigner verify --print-certs manager.apk` and `aapt dump badging manager.apk` help inspect the APK. A filename-derived version is a preparation convenience, not proof of identity. The candidate records that this review is still required.
3. Resolve patch failures against the new source. Never delete a failed hunk merely to make the build finish. Several MuMu fixes address crashes or incorrect credential access, not cosmetic differences.
4. Check whether `native/ksu_probe.c` still matches the new control protocol. Updating the expected UAPI number cannot adapt a changed ioctl structure or syscall transport.
5. Build and test using `upgrade` as above, passing the old and new bundles. Do not separately auto-update Manager while leaving the old kernel module behind.

If an update only changes the Manager and upstream explicitly retains the same kernel API/authentication contract, the kernel component can remain pinned. That still requires a candidate bundle and the same runtime checks.

## C. MuMu changes its kernel: manual port procedure

This is the case that cannot honestly be reduced to "change the version number." Use [the porting notes](PORTING.md) and the measured [original port](../research/MUMU.md) as references.

1. **Capture a clean target.** Save the new `Image` hash, compressed kernel config, release/build strings, Android version, reference vendor module and symbol names. Keep proprietary vendor binaries in ignored local storage; publish fingerprints and derived compatibility findings, not MuMu disks.
2. **Choose an exact kernel source base.** Obtain the vendor's matching sources if available. Otherwise establish the closest Android common base through measured layouts and disassembly. Pin its commit and archive hash. A nominal 4.19/5.10 version match is insufficient.
3. **Measure the ABI.** Compare debug/BTF information in vendor objects with a configured build. Recheck every private structure touched by the selected root/hiding components: notably `task_struct`, `cred`, namespace/mount objects and relevant VFS structures. The existing 24-byte task padding belongs to one fingerprinted kernel; do not carry it forward by assumption.
4. **Audit symbols and lifetime.** Check undefined and dynamically resolved names against the running kernel. Check prototypes, syscall argument conventions, configuration, CFI/PAC rules and exported-symbol policy. A symbol in kallsyms can still refer to freed `__init` memory. That was a real issue in the original port.
5. **Create a schema-2 profile manually.** Copy the old JSON into a new `profiles/ID/` directory, set `schema: 2`, `id`, all new target/source fingerprints, `validation.status: "candidate"`, explicit `build` settings and a copied kernel config. `python3 ksu.py profiles` validates the record and paths. Use the generated candidate format from paths A/B as the template for `build` and `framework` fields.
6. **Adapt the patches, then build.** Change only the measured layout/API assumptions. `preflight` proves patch applicability; a clean compile proves syntax/link preparation; neither proves runtime memory safety.
7. **Test nonpersistent loading in a fresh disposable lab first.** Keep diagnostic logs; no disk recovery copy is created. Check the control API, Manager recognition and unauthorized access before adding boot persistence. Do not hot-unload the pinned root module.
8. **Test the actual installer and updater.** Use a fresh instance, an in-place upgrade, and cold boots with vendor root disabled. Repeat any SELinux/SUSFS qualification separately if those components changed.

Changes to module signatures, read-only hooks, restricted symbol visibility or the boot layout can require a new loader or kernel-image integration. When that happens, implement and test the new mechanism rather than overriding the fingerprint checks on the old one.

## D. Switching root forks

Use a **clean lab instance**. `upgrade` rejects a different Manager package. Forks can differ in allowlist formats, module mounting, SELinux policy and userspace/kernel ABI even when both call themselves KernelSU. Port the new kernel component and probe, pair its own Manager/daemon, and repeat qualification. Remove the previous root framework through its own uninstall procedure before installing another fork. The [framework comparison](../research/ROOT-FRAMEWORKS.md) explains which branches are relevant to MuMu.

## Qualification and promotion

Keep a dated record containing the profile and artifact hashes, source commits, app/kernel fingerprints and these observed results:

- Three full stop/start cycles, including one after vendor root is disabled; no panic, boot loop or failed startup marker.
- Correct Manager status and native API version/UAPI; ordinary ADB stays UID 2000.
- Approved root succeeds; a fresh unapproved identity fails; restarting the app does not silently broaden its grant.
- Required module stages run once per boot. Test mounting/injection modules separately from simple script modules.
- Graphics, input, sensors, audio, networking and the actual apps you depend on work after cold boot.
- If enforcing is claimed: a real forbidden operation is denied, normal app operations succeed, and the policy does not make all app domains permissive. A displayed label is insufficient.
- If SUSFS is claimed: exercise actual path, mount and metadata views from unprivileged processes, including aliases and concurrency. A version response or installed ZIP is insufficient.
- Failed input checks stop before replacing files; handled installation failures stop the affected instance and report the cause. Temporary staging files are cleaned up. No backup or rollback is performed.

Only then change the candidate's `validation.status` to `verified`, record the evidence in the repository, and rebuild its bundle. The changed profile invalidates the previous candidate manifest by design. Commit the new profile/config/patches/docs, run the host checks and GitHub build, and publish a stable release with checksums and corresponding source archives. Experimental findings may be documented alongside it, but must not be presented as verified release features.

The GitHub **Build MuMu module** workflow accepts a checked-in profile ID. CI checks host-side behavior and produces artifacts; it cannot replace actual MuMu guest qualification.

## E. SUSFS updates

SUSFS is independently pinned in `profiles/ID/susfs.json`; updating Next's APK does not update this custom engine. The upstream normal release assets target other kernels. **Build the selected source for MuMu; do not rename a downloaded GKI `.ko`.**

1. Read the upstream [legacy branch](https://github.com/inforcqb/susfs4ksu-lkm/tree/legacy) changes and protocol documentation. Select a full commit deliberately.
2. Create a candidate that keeps the current Next revision unchanged. This copies the core recipe, optional hardening files and symbol catalogue, marking optional components as candidates:

```sh
python3 ksu.py prepare-framework --base mumu-pro-1.9.2-arm64 \
  --id mumu-susfs-candidate \
  --kernel-ref c81cdf51c3bb606836c6fc9a7cc858053eb0bc62 \
  --manager-tag v3.4.2
```

3. Edit only that candidate's `susfs.json`: set `source_commit`, the matching commit-specific `source.url` and its archive `source.sha256`; set the actual `susfs_version` protocol; increment `module_version` and the integer `module_version_code`. Keep `status: "candidate"`. Obtain the archive hash with `shasum -a 256 downloaded-source.tar.gz`. The URL format is `https://codeload.github.com/inforcqb/susfs4ksu-lkm/tar.gz/FULL_COMMIT`. Do not copy a release ZIP's hash into the source-archive field.
4. Review/rebase `susfs-lkm-mumu.patch` against that source. Preserve the 4.19 API/prototype fixes, namespace locking, pre-copy enumeration filter, `O_PATH` handling and pre-DAC permission behavior. If changing the patch for a new source, save it under a **new filename** and point the candidate at it; do not change the old verified profile's patch. Normalize only the files explicitly listed in `normalize_line_endings`.
5. Build both candidate bundles. A clean patch failure is useful evidence that the port needs attention:

```sh
python3 ksu.py build --profile mumu-susfs-candidate
python3 ksu.py build-susfs --profile mumu-susfs-candidate
python3 ksu.py check-susfs-bundle out/mumu-susfs-candidate-susfs
```

6. On a registered fresh test instance containing the old core, use `upgrade` with the old and new core bundles. Install the candidate SUSFS with `install-susfs --instance INDEX --bundle out/mumu-susfs-candidate-susfs --experimental`. For a core-only instance, apply the matched policy with `harden-existing` and the candidate core/SUSFS bundles. Approve Shell first.
7. Run the [guest qualification](../tests/guest/README.md), real app tests, module disable/re-enable and three cold boots. A failed SUSFS startup is skipped by its boot guard; the installer also attempts to disable the module when it can reach Android. There is no disk rollback.
8. Promote the candidate core and optional specifications only after qualification, then build new final bundles. Source archive hashes, module hashes and measured test coverage belong in the release record.

For other forks, choose and port their own engine/userspace contract on a clean lab. The generic candidate machinery does not turn an incompatible fork into a supported one.

## F. SELinux repair updates

The independent recipe is `profiles/ID/hardening.json` plus its `hardening/` directory. A new core profile copies it as a candidate. Copying **does not** prove compatibility with a changed Android system image. The original vendor policy and every patched text file have exact input hashes; a mismatch stops installation before those system replacements.

For a changed ROM:

1. Capture the original policy, init files and file/property/service contexts from a fresh clean lab. Store proprietary inputs locally, not in Git.
2. Compare against the old input hashes. Review service names, command continuation lines and real process domains. Insert an explicit `seclabel` after the complete logical service command, not in a continued argument line.
3. Recreate small exact-input/exact-output patches for the new files. Keep distinct object types and targeted permissions. Investigate denials alongside real functionality instead of mechanically allowing every AVC.
4. Compile from the original vendor policy with the pinned standalone policy utility. Inspect the binary with SETools, especially `sesearch --allowxperm`, and confirm the driver whitelist values. Set `compiled_policy_sha256` to the **inspected result's** hash. The proprietary compiled policy is produced locally during installation and is not redistributed.
5. Review the scoped offline label trees and explicit executable labels. If the disk format/partition layout changed, port the disk adapter first. Do not disable its filesystem, bounds or stopped-instance checks.
6. Test with the boot watchdog and a real forbidden-operation canary. Check fresh app launches and service restarts after enforcement is already on. Confirm graphics, sensors, networking, audio, shell and approved root.
7. Keep the previous policy recipe available for its old verified profile. Promote/rebuild only after a complete fresh `harden-existing` installation and the qualification tests.

`upgrade` preserves an existing hardening installation during a framework-only update. Its recipe identity is based on actual policy/patch/boot-file content and guest destinations, so merely copying it to a new profile name does not invalidate the installed recipe. Changing that content is a policy migration. The current installer refuses to apply a second hardening recipe on top of the first; use a fresh core-only base or implement and qualify an explicit migration. The v1.0.1 recipe adds core-service execution labels and property rules to v1.0.0. A v1.0.0 hardened installation is not silently converted by a core-only upgrade; review and apply the policy delta, regenerate the exact static policy, relabel the listed executables, update the boot scripts and state hash, and repeat app/service/cold-boot qualification. Unreviewed policy combinations are refused.

## Quick decision table

| What changed? | Typical work |
| --- | --- |
| MuMu app only, identical kernel/driver/system inputs | Capture, candidate profile, fresh-lab qualification |
| MuMu Android system files/policy | Rebase the hardening recipe and requalify enforcement |
| MuMu kernel/config/driver | Measure and port the ABI; rebuild both kernel components |
| Next Manager/daemon/legacy source | Explicit `prepare-framework`, patch/protocol review, in-place upgrade |
| SUSFS source/protocol | Candidate SUSFS source pin, port patch, separate build and feature tests |
| Root fork | Clean lab; port and pair that fork's kernel and userspace |

The practical maintenance policy is **manual source selection with automated capture, validation, build, in-place installation and runtime checks**. New upstream code is never loaded merely because it has a higher version number.

## G. Vendor-root cleanup after an emulator update

The exact removal/patch contract is `profiles/ID/vendor-cleanup.json`. It is copied as a candidate when preparing a new profile. On the supported release, run:

```sh
python3 ksu.py clean-vendor-root --instance 4
python3 ksu.py verify-vendor-cleanup --instance 4
```

The command requires working authorized KernelSU and matching enforcing repairs. It stops the instance, examines the private ext4 filesystem directly, checks the known helper/startup/APK fingerprints, removes only the reviewed vendor root helpers and startup code, checks the filesystem, atomically replaces the private disk and verifies the next boot. An already clean instance is verified without rewriting the disk.

For a new MuMu version, inspect the real startup files and companion APK before changing hashes. Review which receiver starts root and which service supplies ordinary emulator integration. The current receiver writes a protected su service-status property and crashes when vendor su is absent; the replacement boot script starts the ordinary API service directly. Preserve graphics, input, sensors and platform IPC. Rebase the two exact text patches, fingerprint any new helper binaries, test the service under enforcement, and repeat cleanup plus cold-boot qualification. Do not convert a checksum rejection into an unconditional recursive deletion.

## H. v1.0.1 to v1.0.2: preserve the SELinux-hiding switch

Use the v1.0.2 repository tag and keep the old/new distribution bundles available while updating:

```sh
python3 ksu.py upgrade --instance 4 \
  --from-bundle out/releases/v1.0.1/core \
  --bundle out/releases/v1.0.2/core
python3 ksu.py verify-hardening --instance 4
```

Substitute your actual instance index. This is an in-place update; no instance or disk backup is created. The updater recognizes only the fingerprinted v1.0.1 boot recipe in `hardening/startup-migrations.json` and verifies the unchanged policy and system files before replacing `guard.sh` and its state identity. The normal core update replaces `boot.sh` and its payload checksum. SUSFS and the compiled policy are unchanged.

Then choose **Hide SELinux modification** in Next's Settings. Its saved value survives cold boot; unset preferences use the legacy kernel's On default. For scripted maintenance, `ksud feature set 4 1` changes the live setting and `ksud feature save` persists current feature settings. Use value `0` to turn it off. These commands require your existing authorized root shell. Neither value changes real SELinux enforcement.

`verify-hardening` reports both the live and saved hiding values for inspection. Neither is a pass/fail requirement: both are valid user preferences. Enforcement, critical labels, installed hashes and core service health remain mandatory.


## Reviewing a future service-policy change

1. Inventory the vendor services, identities and device/configuration dependencies. Include operations performed after startup and when input/media sessions are recreated.
2. Update the complete functional permission set for the responsible services. Keep ordinary-app restrictions and verify them with the APK canary test.
3. Compile from the new MuMu image's exact original policy. Compare semantics with SETools; pin every accepted serialization. Do not replace an expected hash merely because the compiler produced a different file.
4. Recheck `binary_repairs`. The optimizer edit applies only to the exact helper hash in the profile. If MuMu fixes or changes that helper, review its behavior and remove or rederive the edit; never reuse offsets on an unknown binary.
5. Add explicit previous-recipe, policy, helper and boot-file fingerprints to `policy-migrations.json`. Test rejection of altered input and a real migration, including the read-only remount after replacing a running helper.
6. Run the video/native-input tests, appropriate service lifecycle checks and cold boots. Do not hot-kill the central bridge as a routine health check; its supported lifecycle is the full emulator lifecycle.
7. Publish the installer and payload together, with concise installation instructions and a separate validation record. Remove local builds, installed probes and staging files after publishing.
