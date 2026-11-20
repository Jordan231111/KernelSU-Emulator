# SELinux and SUSFS

## Settings

- Keep real **SELinux enforcing**, MuMu's disk **Writable**, and vendor root **Off**.
- **Hide SELinux modification** can be On or Off. Both saved choices persist through reboot; the unset default is On.
- Leave **AVC spoofing Off** by default. KernelSU's feature 10003 has no connected audit hook in this legacy integration. The separate SUSFS `enable_avc_log_spoofing` command is implemented and tested; it changes audit text, not access decisions.

The hiding switch sanitizes selected context/access queries and status counters. It does not disable access checks. Maintenance verifies the actual flag through a root-side read of `/sys/fs/selinux/enforce`.

## Enforcement

The compatibility policy gives trusted MuMu services the virtual-hardware access they require while retaining ordinary-app isolation. KernelSU's root domain is privileged. See [service permissions](SERVICE-POLICY.md) for the scope and shared-domain tradeoffs.

Installation compiles policy with the checksum-pinned standalone `magiskpolicy` utility from Magisk v31.1. The installer also accepts the reviewed v27.0 policy serializations on existing installations. With this profile's original vendor input and rules, SETools `sediff` found identical policy semantics for the v27.0 and v31.1 compiler outputs.

## SUSFS package

The `mumu_susfs` KernelSU package contains the MuMu-compatible kernel module, Sidex's universal `ksu_susfs` client, the raw `susfs-sc` client, boot scripts, and payload checksums. At boot it hides the KernelSU/SUSFS module names, registers known root/policy paths, enables mount filtering and hides the root Manager's UID from other apps' priority queries.

Defaults cover `/data/adb`, the installer's system paths, and a persistent rule for
the late-created Disk Cleanup socket. Additional modules and apps may need
separate rules. Root authorization does not exempt an app's ordinary process from
every filter.

The [Sidex module](https://github.com/sidex15/susfs4ksu-module) is the userspace configuration/service layer. Its canonical kernel component lives in [simonpunk's GitLab repository](https://gitlab.com/simonpunk/susfs4ksu). GitLab is not evidence of an unofficial or abandoned implementation. The canonical **kernel-4.19** branch is v1.5.5 at `001e69919c6271f690fd00b17e4c721c9e599152`; the maintained **gki-android12-5.10** branch is v2.4.0 at `784ac9e6fd49bb02499b5b60c57ccc9d0c680204`.

MuMu retains its proprietary 4.19.195 Image and drivers. The installed engine is an independent LKM: current [main `761b930`](https://github.com/inforcqb/susfs4ksu-for-lkm/tree/761b93083afd846858257221453bf306465042a3), replacing the previous legacy `0b197bf`, with this repository's MuMu patch. The port now implements both v2.4 UID-filter commands and reports that wire-protocol version. This does not claim that it is the canonical built-in kernel implementation. The [current universal client `14b5773`](https://github.com/sidex15/susfs4ksu-binaries/tree/14b577368caf43c84577918f5d8ba6cae56c8d63) is included with corresponding source. Sidex's separate R28 service/WebUI package is not installed alongside the MuMu startup/configuration owner.

The feature list reports implemented command families; rules and caller identity determine their effects. Kstat, redirection and mapping rules are empty at normal startup. Package visibility is handled separately by installed add-ons. No result below establishes hardware-backed attestation or universal resistance to detection.

## Feature audit on MuMu instance 0, 2026-11-20

These are guest observations, not conclusions inferred from an advertised capability. Tests use root and zero-capability UID 19999 in an app SELinux domain, plus the real diagnostic APK where stated. JSON records carry the kernel-module hashes and boot ID.

| Feature | Canonical specification / independent legacy | MuMu implementation and startup | Controlled expected → observed |
| --- | --- | --- | --- |
| Path hiding | 4.19 uses inode flags and VFS hooks; legacy LKM uses inode rules | Pre-DAC denial plus LSM checks; default root/policy paths registered | App stat/open/O_PATH: ENOENT; no directory entry; root visible → passed with modes 644/600 unchanged |
| Directory entries / aliases | Canonical filters before copying dirents | Pre-emission filter now matches filesystem + inode and honors ownership | Hardlink omitted, symlink target access denied, caller-owned file visible → passed. Equal inode 12 on two ext4 filesystems does not cross-match |
| Concurrency | Canonical checks before emitting results; legacy post-copy paths can expose transient data | Directory filtering before emission; kstat rewritten inside 4.19 `vfs_getattr` | 72,000 path operations + 10,000 directory reads: zero names leaked; 160,000 concurrent stat calls: zero original-inode observations |
| Path loop | New canonical retries registered names during app specialization; legacy LKM only retried initially absent files for a bounded period | Persistent loop rules refresh in task work before an app UID transition returns to userspace; initial missing paths also retry | Initially absent file hidden; replacement inode hidden in the next app process → passed |
| Path UID selection | Added in canonical 2.4; absent from independent main/legacy | New canonical command; default retains existing all-app coverage until explicitly configured | Selected package UID hidden, unselected UID visible, invalid configuration preserves prior selection → passed |
| Mount views | 4.19 hides registered mounts for all processes; newer canonical gates non-root processes and marks mounts during allocation | MuMu tracks individual mounts with genuine high IDs, preserves tags through clones, and removes stale translations; FD reads derive the visible ancestor directly even when the cache is full | Unregistered KSU bind hidden; original /data visible; 120 FD-first namespaces, 200 reuse cycles, off/on, and 1,100 simultaneous mounts beyond cache capacity pass |
| Automatic KSU/bind tagging | Built-in canonical patches mount allocation/attach and namespace state | New KSU mount trees are marked before attach propagation; cloned mounts inherit the mark; existing explicit prefix rules remain available | Controlled whole-filesystem bind outside configured prefixes is hidden automatically without hiding its original. Zero allocation failures or missed lifecycle probes in the qualification |
| Static kstat | Canonical user-selected metadata; independent LKM syscall hooks | Kernel-side rewrite before userspace copy; no default rules | App inode 12345/size 4242, root original metadata → passed |
| Dynamic/full-clone kstat | Preserve original identity; full clone also preserves size/link count | Fixed supercall discarding the full-clone flag | After replacement: normal update size 18; full clone original size 8; both original inode → passed |
| Overlay metadata/directories | Optional 4.19 SUS_OVERLAYFS; removed from newer canonical configuration; absent from independent LKM | Added 4.19 lower-path/getattr/statfs/directory callbacks for filtered apps; root retains real view | After copy-up: app size 8, root size 18; app ext4 magic and actual lower mount flags; upper-only name omitted → passed |
| Uname | Spoof release/version for callers | Implemented; unset at boot | Both root and app see controlled `4.19.195-ksu-qa` and version → passed; reboot clears test values |
| Logging | Runtime log control | Implemented, Off at boot | On/off/on/off readback → 1/0/1/0 |
| Kernel/module symbols | Canonical filters kallsyms; LKM also hides module/sysfs entries | Fixed 4.19 iterator layout (no BPF position field); offsets checked at build | KernelSU/SUSFS omitted from modules and zero tagged kallsyms lines; vendor vaddress retained → passed |
| Cmdline / bootconfig | Non-GKI uses cmdline; GKI uses bootconfig | MuMu cmdline implemented; bootconfig is not its interface; unset at boot | Controlled cmdline replaces proc view → passed; reboot clears it |
| Open redirection | Canonical UID schemes and reverse views; legacy LKM provides syscall redirection | 4.19 filename ownership and IN_OPEN fixed; automatic reverse kstat added; no default rules | App reads replacement, root original; app FD path and inode both match original; redirected file emits IN_OPEN → passed |
| Mappings | New canonical covers maps, smaps, rollup, map_files, mem, pagemap; absent in canonical 4.19 | Ported 4.19 page-walk/GUP signatures; added pre-emission map_files iterator and lookup/cache rejection; no default rules | App maps/smaps/range listing absent, readlink ENOENT, pagemap zero, mem EIO; root real view; 8 MiB mapped file adds 0 KiB to app rollup versus 8192 KiB before/root → passed |
| Priority UID filter | Added in canonical 2.4; absent from independent main/legacy | Native get/setpriority and ioprio get/set wrappers; root Manager selected at boot | Four other-UID queries return ESRCH, root/self work; package removal drops stale UID → passed |
| AVC log spoofing | Newer canonical substitutes audit contexts | Independent engine's hook works with MuMu's argument layout; default Off | Two enable cycles rewrite controlled ksu target to priv_app, while reads remain EACCES and enforcement stays 1 → passed |
| TRY_UMOUNT / automatic try-unmount / SUS_SU | Public in old 4.19; deprecated/removed from current canonical dispatch | No obsolete command emulation; ordinary KernelSU unmount/authentication remains separate | Old TRY_UMOUNT leaves unsupported sentinel 126 and returns EINVAL, matching current dispatch behavior |
| AArch32 | Independent LKM has compatibility paths | MuMu refuses the 32-bit test executable | Guest reports “not executable: 32-bit ELF file”; ARM64 is the qualified execution ABI |

**Verdict:** the maintained LKM plus MuMu changes supplies tested implementations of the current public command families, including the v2.4 additions. It is not full canonical-kernel parity. The canonical patches directly modify inode/address-space flags, task flags, mount-ID allocation, namespace/unmount transitions and early KernelSU integration. Reproducing those original internals requires a matching kernel source build and compatible MuMu drivers; loading the canonical 5.10 patch into an unchanged 4.19 Image cannot do that. The LKM instead uses measured callbacks and side tables. The table identifies the remaining semantic differences explicitly.

The audit fixed trial startup failures in 4.19 `filename_parentat` ownership and the missing exclusive-lookup helper, plus O_PATH handling, hardlink/filesystem identity, symbol layout, map_files exposure, loop refresh, full-clone flags, overlay views and redirected-FD metadata. Failed trial binaries are not the delivered build. Hot unload remains disabled because callbacks and 4.19 procfs lifetimes require a cold boot to remove the engine.

The final mount-capacity regression fills the upstream 1,024-entry ID cache.
Package 1.2.2 exposed fdinfo mount ID `2000001110`, absent from the app's mount
table. Package 1.2.3 derives the visible ancestor from the live, referenced mount
and returns `2619`, present in that table, under the same 1,100-mount fixture.
Cached translation remains a fallback if the descriptor closes during the read.

## Metamodules

A metamodule supplies KernelSU's mounting/installation infrastructure. It can choose OverlayFS, bind mounts or another strategy and cooperate with SUSFS; it is not itself proof of root hiding. The installed modules expose no `system/` payload, so this setup currently needs no metamodule. Adding an unused mounting layer would not improve the verified path/map/UID behavior. A future module that replaces system files needs a compatible mounting provider and a fresh check of its actual mounts.

## Verification and removal

```sh
python3 ksu.py verify-hardening --instance INDEX
python3 ksu.py verify-susfs --instance INDEX
```

`verify-susfs` checks the boot readiness property, fallback state, protocol version and variant. The reported path counters accumulate during the current boot. An increase in `precopy_hidden` records directory entries the port filtered. The command reports `behavior_tested: false` because it performs no per-feature exercise. The [guest tests](../tests/guest/README.md) have separate behavioral checks.

To stop loading SUSFS, disable **MuMu SUSFS** in Next's Modules screen and cold-boot. Keep SELinux enforcing. Do not hot-unload either kernel module.
