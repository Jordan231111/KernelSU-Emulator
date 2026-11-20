# MuMu Disk Cleanup

The core bundle includes the Disk Cleanup compatibility fix. Both `install` and
`upgrade` install its client, service, policy, init entry, and checksums. No
separate script, root grant to the vendor app, SDK download, or manual setup is
needed. `verify --root` checks the service's UID, SELinux domain, capabilities,
and syscall filter as well as ordinary KernelSU operation.

## Cause and repair

MuMu 1.9.2's Data → Clean button calls its Android API service. That service
launches `su` and writes `fstrim /data && sync` with a fixed exit-status suffix.
MuMu's Java runtime translates the executable to `/system/xbin/mu_bak`.
Removing that legacy root provider broke cleanup. The host UI misleadingly
reported that the device had already been cleaned when the guest logged
`trim data failed`.

The MuMu kernel patch redirects **only** that legacy executable request from
the vendor API's system-UID process, including its Binder-thread children, to
the cleanup client. It does not grant root, create a `su` or `mu_bak` file, or
change ordinary applications' `su`, access, or stat behavior. The client checks
UID 1000 and accepts only the vendor's fixed request; it never evaluates shell
text or forwards a caller-selected path.

The client talks to `mumu_disk_cleanup`, a dedicated init service. The service
opens `/data`, binds its protected Unix socket, drops to UID/GID 1000 with no
supplementary groups, and retains only `CAP_SYS_ADMIN`, which FITRIM requires.
Its SELinux domain is `mumu_disk_cleanup`. It checks the connecting UID and
`system_app` security context. Its seccomp filter permits FITRIM only on that
pre-opened descriptor and blocks execution, path opens, mounts, and forks.
`NoNewPrivs=1` and a restricted capability bounding set persist for its lifetime.
An ordinary app cannot connect to the socket. The bundled SUSFS startup also
registers a persistent path rule for its late-created inode, so app stat and
connect calls return ENOENT instead of revealing its existence through EACCES.
Existing KernelSU grants remain under Manager control.

The client is freestanding ARM64 code built by the repository's existing Docker
toolchain. A trial linked against desktop glibc was killed with SIGSYS when
launched by the actual Android app, whose seccomp policy is inherited by
children. A shell-only launch did not reproduce that failure. The packaged
client uses the Android-compatible syscall interface directly.

Calling Android's ordinary storage service was also tested: it reported
completion without a `/data` trim because this MuMu image does not register that
filesystem in the service's fstab. The delivered helper issues FITRIM directly
on the mounted filesystem. It does not alter fstab, resize partitions, copy VM
images, or modify the live qcow2 file from the host.

## Qualification

Instance 0's initial `data.qcow2` allocation was 110,097,858,560 bytes. A real
trim reduced it to 97,357,660,160 bytes, reclaiming 12,740,198,400 bytes. The file's
logical length remained 110,169,161,728 bytes: sparse-file allocation, not that
maximum length or the guest's virtual capacity, measures reclaimed host space.

After installing the packaged fix and cold-booting, the **actual MuMu button**
reclaimed a newly allocated/deleted 256 MiB test file. Host allocation fell from
97,665,941,504 to 97,373,913,088 bytes. The UI reported **Cleanup Successful**, with
**0.27 GB** cleaned and **90.69 GB** occupied. A retained random file's SHA-256
was unchanged. MuMu labels its GiB-based display as GB.

Package 1.2.2 also passed the actual button with socket hiding
enabled: 97,653,882,880 → 97,377,058,816 allocated bytes, with **Cleanup
Successful / 0.26 GB** shown. The ordinary diagnostic APK observed ENOENT for
both socket stat and connect; the zero-capability system-UID request still
completed. Three subsequent cold boots preserved these results.

The same client/service and hidden-socket checks passed again with final SUSFS
1.2.3 in the controlled cleanup suite; its kernel change concerns fdinfo IDs.

The measurements above retain the UI qualification results.
`tests/guest/qualify_disk_cleanup.py --instance 0` reproduces checks of the fixed
request, rejected callers and commands, disconnect handling, retained data,
physical allocation, and the running service's restrictions. Its controlled
native identities complement the actual vendor-app UI test; they do not replace
it. The diagnostic APK separately checks path visibility and socket denial from
an ordinary app process.
