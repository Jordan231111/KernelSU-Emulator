# Root frameworks and MuMu: source review, 2026-10-15

**Selected base: KernelSU Next's legacy kernel branch, paired with the official v3.4.2 Manager and daemon.** This combination has actually booted and granted and denied root correctly on the fingerprinted MuMu 4.19 kernel. A different Manager cannot supply kernel features that were never compiled, loaded, and connected to its control protocol.

This review covers the original framework and the substantial public fork lineages found during research, including renamed and archived projects. It does not count each device-specific kernel build, rebadged APK, or personal GitHub fork as a separate root architecture. Features below are upstream source/documentation findings; **only the MuMu validation record establishes local runtime support**. Release and branch information is a dated snapshot.

## What the feature names mean

| Layer | What it does | What it does not establish |
| --- | --- | --- |
| Kernel root | Lets approved processes receive privileged credentials, under Manager-controlled profiles | That an arbitrary prebuilt module fits MuMu's kernel |
| Root/module profiles | Control grants, capabilities, SELinux rules and whether an app sees module mounts | Complete invisibility to every app |
| Mounting backend / metamodule | Makes module-supplied system files visible through overlay or bind mounts | Kernel-level SUSFS support |
| Zygisk or a fork's equivalent | Loads native extensions into Android app processes | A requirement for basic `su`, or the same thing as kernel root |
| SUSFS | Alters selected kernel filesystem/process observations through kernel patches or a compatible implementation | Device certification or a hardware-backed trusted boot chain |
| KPM | Loads additional KernelPatch-style kernel extensions | That an extension or its hook engine supports this vendor kernel |
| SELinux enforcing | Blocks operations forbidden by the actual loaded policy | That a displayed status string proves enforcement |

These are independent layers. Choosing the longest feature list often adds several engines and version dependencies. The useful question is which capabilities work together on the target and have a maintainable update path.

## Framework comparison

| Project / checked state | Distinguishing capabilities and maintenance findings | Assessment for this MuMu target |
| --- | --- | --- |
| [KernelSU](https://github.com/tiann/KernelSU), v3.3.1 | Original actively maintained framework; app profiles, module infrastructure and metamodules. Current official support centers on GKI 5.10+. Historical non-GKI integration is documented separately. | Original v0.9.5 was our first working proof. A current official GKI binary is not a drop-in for MuMu 4.19. |
| [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next), v3.4.2 | Active development plus a separate legacy branch. Modern Manager/daemon, profiles, metamodules, SUSFS queries and an embedded GKI SUSFS loader. Older feature charts miss these changes. | **Working selected base.** MuMu needs our measured legacy port and a separate 4.19 SUSFS binary; the daemon's embedded GKI assets do not fit it. |
| [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra), v4.2.1 | Broad customization and KPM integration. The `main` and `builtin` branches differ: the reviewed built-in branch contains SUSFS configuration that must not be assumed present in every main-branch LKM. | Credible source-integration alternative. Changing to its APK alone would not provide SUSFS on MuMu. Its kernel hooks and userspace contract would need a separate port. |
| [BakaSU](https://github.com/Baka-SU/BakaSU), formerly ReSukiSU; v4.2.0-rc3 | The old ReSukiSU URL redirects here. Reviewed releases are candidates. Supports legacy/manual integration paths, metamodules, SUSFS integration and multiple Manager identities. Tracepoint and non-GKI paths have different prerequisites. | Relevant for a future full kernel integration, but not a more mature, already-tested replacement for the working MuMu port. |
| [YukiSU](https://github.com/Rouyashiki/YukiSU), formerly Anatdx/YukiSU; v1.7.0 | Built-in YukiZygisk, SuperKey/dynamic Manager concepts and additional presentation controls. Current documentation targets ARM64 GKI 5.10+ LKM and excludes non-GKI/built-in integration. | Attractive integrated features, incompatible with treating this 4.19 target as a supported prebuilt installation. |
| [FinaSU](https://github.com/LyraVoid/FinaSU), v0.1.0-dev1 | FolkZygisk, Sui, Folk-Mount/NoMount and capability-gated SUSFS integration. Includes legacy/manual integration claims. Release names remain development/preview even when GitHub's prerelease flag is false. | Rich integrated feature set, but development maturity and an untested MuMu port make it unsuitable as our stable default. |
| [MakoSU](https://github.com/Spring-bulid/MakoSU), v4.1.9 | Suki-derived work emphasizing GKI/KMI handling, KPM, recovery and managed SUSFS configuration. | A distinct downstream integration effort; its phone/GKI release assets do not solve MuMu's vendor ABI. |
| [RKSU / rsuntk](https://github.com/rsuntk/KernelSU), v3.2.2-10-legacy | Upstream-derived development with explicit legacy releases and several integration branches. Exact branch and hook backend matter more than the short project name. | A useful legacy-port source and comparison. No additional MuMu runtime evidence establishes an advantage over the selected Next port. |
| [MKSU / 5ec1cff](https://github.com/5ec1cff/KernelSU/tree/mksu), `mksu` branch; release tag v9.9.9 | Important alternative development lineage, historically associated with mount changes. Current branch material also discusses metamodules. The sentinel-style release tag is not evidence of greater maturity than a numerically lower release elsewhere. | Useful source research; selecting a branch, matching Manager and requalifying the module would still be necessary. |
| [backslashxx's KernelSU](https://github.com/backslashxx/KernelSU), v3.3.1-3 | Active upstream-contributor/porting tree with numerous manual-hook, compatibility and experimental branches. | Valuable for legacy integration techniques; evaluate the exact commit rather than assigning all branch features to one binary. |
| [KOWSU](https://github.com/KOWX712/KernelSU) | Personal upstream-derived development with a different Manager UI; no releases in the reviewed release feed. | Manager/UI preference does not eliminate kernel compatibility work. Not a ready packaged MuMu replacement. |
| [Wild_KSU](https://github.com/WildKernels/Wild_KSU), v3.1.2, archived | The framework repository is archived. This is separate from continuing activity in WildKernels' kernel-building and testing projects. | Do not choose an archived framework solely because a similarly named kernel build project is active. |

Source details that resolve common chart errors: [Next v3.4.2 metamodule implementation](https://github.com/KernelSU-Next/KernelSU-Next/blob/v3.4.2/userspace/ksud/src/metamodule.rs), [SukiSU main Kconfig](https://github.com/SukiSU-Ultra/SukiSU-Ultra/blob/main/kernel/Kconfig), [SukiSU built-in Kconfig](https://github.com/SukiSU-Ultra/SukiSU-Ultra/blob/builtin/kernel/Kconfig), [BakaSU release feed](https://github.com/Baka-SU/BakaSU/releases), [FinaSU release feed](https://github.com/LyraVoid/FinaSU/releases).

Next's [pinned SUSFS userspace implementation](https://github.com/KernelSU-Next/KernelSU-Next/blob/v3.4.2/userspace/ksud/src/susfsd.rs) recognizes the reboot control protocol used by the independent LKM. Its automatic loader selects compiled-in assets by GKI KMI. We retain its version/feature queries and use a standard KernelSU module to load the specifically compiled MuMu engine.

## Related projects that are not KernelSU forks

**[APatch](https://github.com/bmax121/APatch)** uses the separate KernelPatch architecture. Its kernel patches and KPM ecosystem are relevant alternatives, but an APatch Manager installation is not a substitute for integrating KernelPatch into MuMu's raw kernel/boot arrangement. The reviewed release was 11282. No APatch-on-MuMu runtime result is claimed here.

**[Magisk](https://github.com/topjohnwu/Magisk)** has a different boot/userspace-root architecture, a substantial module ecosystem and Zygisk. The reviewed release was v30.7. MuMu's private-system startup path could support a separate Magisk port, but replacing a functioning kernel-root solution with it does not automatically improve concealment or preserve the same profiles.

**KPM is no longer a useful yes/no shortcut for choosing SukiSU.** [KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next) and its [module integration](https://github.com/KernelSU-Next/KPatch-Next-Module) are separate work in that ecosystem. Their existence is not proof of compatibility with this 4.19 port; the root release does not silently install them.

## SUSFS is a kernel feature, not just a module ZIP

[Canonical SUSFS](https://gitlab.com/simonpunk/susfs4ksu) supplies kernel changes and controls for selected path, mount, metadata and other observations. Its older `kernel-4.19` branch demonstrates that **4.19 is not inherently too old for SUSFS**. That source-integration route changes kernel code and, depending on revision, private structures. A compatible complete MuMu kernel would have to preserve its vendor driver ABI and emulator behavior.

The [sidex15 userspace module](https://github.com/sidex15/susfs4ksu-module) configures an already-supported kernel. The [legacy Next integration tree](https://github.com/sidex15/KernelSU-Next) is a source integration, not evidence that installing the ZIP makes an arbitrary stock kernel support SUSFS. Match the actual kernel API, integration branch and userspace release together.

The independent [SUSFS LKM implementation](https://github.com/inforcqb/susfs4ksu-lkm) offers another route: retain MuMu's vendor kernel and add a compatible extra module. Its normal release assets target GKI kernels. Its [legacy porting document](https://github.com/inforcqb/susfs4ksu-lkm/blob/legacy/LEGACY_PORTING.md) explicitly described pre-5.10 support as unbuilt and untested when checked. We therefore treated it as source to port, not a ready-to-install release.

Our local investigation progressed beyond that baseline: old procfs/LSM/syscall APIs, absent `statx` mount-ID fields, command-line handling and namespace locking needed changes. In particular, a 4.19 namespace has no `ns_lock`; replacing that nonexistent member with guessed padding is wrong. The port must use the real namespace lock in sleepable context and defer work out of probes. A successful compile and symbol match are preliminary checks, not completed feature validation. The completed MuMu port and its measured boundaries are documented in [SELinux/SUSFS](../docs/SELINUX-SUSFS.md) and [validation](../docs/VALIDATION.md).

## Concealment and integrity are different tests

There is no defensible promise that any combination is universally "undetectable." Concealment depends on the observer, module mounts, injection components, kernel behavior and emulator-specific signals. A kernel LKM implementation can itself introduce inconsistencies. For example, [Wild Detector](https://github.com/WildKernels/Wild_Detector) documents checks aimed at directory enumeration races and path-opening behavior in SUSFS-style LKM implementations. This is useful adversarial validation evidence, not a reason to substitute a status screenshot for measurements.

Google's [Play Integrity verdict documentation](https://developer.android.com/google/play/integrity/verdicts) describes requirements involving certified devices and hardware-backed boot integrity, and a separate eligible virtual-environment verdict. Root hiding does not manufacture those properties for an arbitrary MuMu instance. Likewise, genuine SELinux enforcement improves access control but does not turn the emulator into a certified physical phone.

## Choice for this repository

Keep **Next as the independently verified root base**. Qualify optional mounting/injection components individually. Treat SUSFS as a separate kernel compatibility deliverable, with its own pinned source and behavior tests. Prefer real enforcing policy repairs over reporting a fake enforcement state. Maintenance updates the explicitly selected instance in place and creates no backups or recovery copies. New kernel ports can be qualified in an optional fresh, empty lab; no existing instance is cloned.

This selection prioritizes usable features, measured compatibility and maintainable upgrades. It can change when another fork demonstrates a concrete benefit on MuMu and passes the same checks. The [update workflow](../docs/UPDATING.md) makes that decision explicit instead of silently following a moving branch.
