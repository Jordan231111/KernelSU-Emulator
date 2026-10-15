# Updating MuMu or KernelSU without losing the working installation

The update unit is a **compatibility profile plus its complete bundle**: kernel module, official Manager, daemon, startup scripts and source archives. Keep those together. An APK update by itself is not the update procedure for this custom port.

The tools distinguish `verified` profiles from `candidate` profiles. A candidate can be built and inspected normally, but installation requires `--experimental` and an instance registered by `create-lab` or `clone-lab`. This flag permits testing; it does not certify the result. No command automatically installs the latest GitHub commit or promotes a profile.

## Before an update

1. Keep the current complete bundle, its `manifest.json`, and installation recovery directory.
2. Keep access to the tested MuMu application version. An instance clone preserves instance files; **it does not freeze the MuMu application, hypervisor, or shared boot resources**. An app update can change the engine used by all instances.
3. Run `python3 ksu.py list` and identify the working instance by both index and name. The examples below use **4 as the source** and **6 as a test clone**. Substitute the indexes actually returned on your computer.
4. Check the current installation, then make a separate test copy:

```sh
python3 ksu.py verify --instance 4 --root
python3 ksu.py clone-lab --instance 4 --name 'KernelSU Update Lab'
python3 ksu.py start --instance 6
python3 ksu.py capture --instance 6 --root --output out/captures/before-update
```

`clone-lab` stops its source long enough to clone a consistent disk and restarts it if it was running. It never selects `all`. If the source was stopped, it stays stopped. The registration records the clone's actual bundle path, so a later instance reusing the same numeric index does not inherit permission to test candidates.

`capture` reads the running kernel identity/configuration, host kernel image, vendor reference module, available symbol names and SELinux observations. It does not install a module or turn on vendor root. With `--root`, Shell must already have a KernelSU grant. Capture directories are new, checksum-recorded snapshots; use a new directory name each time.

A private writable disk can also retain the older Android system after the host app is updated. Testing that retained disk under a new app version is different from testing the new version's fresh system image. Use a fresh lab instance to qualify the latter; do not infer a system-image upgrade from the host app's version number alone.

## Which update path applies?

After installing the MuMu version you want to investigate, capture the test instance again:

```sh
python3 ksu.py capture --instance 6 --root --output out/captures/new-mumu
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

To update an existing installation, use a new clone:

```sh
python3 ksu.py upgrade-clone --instance 4 \
  --from-bundle out/mumu-pro-1.9.2-arm64 \
  --bundle out/mumu-new-arm64 --experimental \
  --name 'KernelSU New MuMu Test'
```

Authorize Shell in the source Manager first. Use the **new index printed by this command** for verification. The command verifies every installed payload file and the installed Manager APK against `--from-bundle`, replaces the complete payload in the clone, updates the same-package Manager, tests startup using the already-authorized KernelSU Shell grant and keeps vendor root off. A different signing identity is rejected by Android's APK update rules.

If the operation fails, the clone is stopped and the original instance remains the recovery copy. This is deliberate: a system-disk-only rollback cannot undo an APK/database migration in `/data`. Keep the original until the new clone has passed your actual app/module tests.

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
5. Build and test using `upgrade-clone` as above, passing the old and new bundles. Do not separately auto-update Manager while leaving the old kernel module behind.

If an update only changes the Manager and upstream explicitly retains the same kernel API/authentication contract, the kernel component can remain pinned. That still requires a candidate bundle and the same runtime checks.

## C. MuMu changes its kernel: manual port procedure

This is the case that cannot honestly be reduced to "change the version number." Use [the porting notes](PORTING.md) and the measured [original port](../research/MUMU.md) as references.

1. **Capture a clean target.** Save the new `Image` hash, compressed kernel config, release/build strings, Android version, reference vendor module and symbol names. Keep proprietary vendor binaries in ignored local storage; publish fingerprints and derived compatibility findings, not MuMu disks.
2. **Choose an exact kernel source base.** Obtain the vendor's matching sources if available. Otherwise establish the closest Android common base through measured layouts and disassembly. Pin its commit and archive hash. A nominal 4.19/5.10 version match is insufficient.
3. **Measure the ABI.** Compare debug/BTF information in vendor objects with a configured build. Recheck every private structure touched by the selected root/hiding components: notably `task_struct`, `cred`, namespace/mount objects and relevant VFS structures. The existing 24-byte task padding belongs to one fingerprinted kernel; do not carry it forward by assumption.
4. **Audit symbols and lifetime.** Check undefined and dynamically resolved names against the running kernel. Check prototypes, syscall argument conventions, configuration, CFI/PAC rules and exported-symbol policy. A symbol in kallsyms can still refer to freed `__init` memory. That was a real issue in the original port.
5. **Create a schema-2 profile manually.** Copy the old JSON into a new `profiles/ID/` directory, set `schema: 2`, `id`, all new target/source fingerprints, `validation.status: "candidate"`, explicit `build` settings and a copied kernel config. `python3 ksu.py profiles` validates the record and paths. Use the generated candidate format from paths A/B as the template for `build` and `framework` fields.
6. **Adapt the patches, then build.** Change only the measured layout/API assumptions. `preflight` proves patch applicability; a clean compile proves syntax/link preparation; neither proves runtime memory safety.
7. **Test nonpersistent loading in a disposable clone first.** Keep host-side logs and an offline system-disk recovery copy. Check the control API, Manager recognition and unauthorized access before adding boot persistence. Do not hot-unload the pinned root module.
8. **Test the actual installer and recovery.** Use a clean instance, then a clone upgrade, cold boots with vendor root disabled, and explicit restoration. Repeat any SELinux/SUSFS qualification separately if those components changed.

Changes to module signatures, read-only hooks, restricted symbol visibility or the boot layout can require a new loader or kernel-image integration. When that happens, implement and test the new mechanism rather than overriding the fingerprint checks on the old one.

## D. Switching root forks

Use a **clean lab instance**. `upgrade-clone` rejects a different Manager package. Forks can differ in allowlist formats, module mounting, SELinux policy and userspace/kernel ABI even when both call themselves KernelSU. Keep the old working instance as recovery, port the new kernel component and probe, pair its own Manager/daemon, and repeat qualification. The [framework comparison](../research/ROOT-FRAMEWORKS.md) explains which branches are relevant to MuMu.

## Qualification and promotion

Keep a dated record containing the profile and artifact hashes, source commits, app/kernel fingerprints and these observed results:

- Three full stop/start cycles, including one after vendor root is disabled; no panic, boot loop or failed startup marker.
- Correct Manager status and native API version/UAPI; ordinary ADB stays UID 2000.
- Approved root succeeds; a fresh unapproved identity fails; restarting the app does not silently broaden its grant.
- Required module stages run once per boot. Test mounting/injection modules separately from simple script modules.
- Graphics, input, sensors, audio, networking and the actual apps you depend on work after cold boot.
- If enforcing is claimed: a real forbidden operation is denied, normal app operations succeed, and the policy does not make all app domains permissive. A displayed label is insufficient.
- If SUSFS is claimed: exercise actual path, mount and metadata views from unprivileged processes, including aliases and concurrency. A version response or installed ZIP is insufficient.
- Clean-install recovery and clone-upgrade recovery behave as documented. Retain the original instance through qualification.

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

6. Use `upgrade-clone` with the old and new core bundles to make a test copy of the existing enhanced instance. Use its printed index with `install-susfs --bundle out/mumu-susfs-candidate-susfs --experimental`. A core-only source can instead use `enhance-clone` with both candidate bundles. Approve Shell in the source first.
7. Run the [guest qualification](../tests/guest/README.md), real app tests, module disable/re-enable, and three cold boots. The old source instance remains recovery. A failed SUSFS startup is disabled by the installer when it can recover the guest.
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
7. Keep the previous policy recipe available for its old verified profile. Promote/rebuild only after a complete fresh `enhance-clone` installation and the qualification tests.

`upgrade-clone` preserves an existing hardening installation during a framework-only update. Its recipe identity is based on actual policy/patch/boot-file content and guest destinations, so merely copying it to a new profile name does not invalidate the installed recipe. Changing that content is a policy migration. The current installer refuses to apply a second hardening recipe on top of the first; use a new core-only base or implement and qualify an explicit migration.

## Quick decision table

| What changed? | Typical work |
| --- | --- |
| MuMu app only, identical kernel/driver/system inputs | Capture, candidate profile, clone qualification |
| MuMu Android system files/policy | Rebase the hardening recipe and requalify enforcement |
| MuMu kernel/config/driver | Measure and port the ABI; rebuild both kernel components |
| Next Manager/daemon/legacy source | Explicit `prepare-framework`, patch/protocol review, clone upgrade |
| SUSFS source/protocol | Candidate SUSFS source pin, port patch, separate build and feature tests |
| Root fork | Clean lab; port and pair that fork's kernel and userspace |

The practical maintenance policy is **manual source selection with automated capture, validation, build, clone installation and recovery**. New upstream code is never loaded merely because it has a higher version number.
