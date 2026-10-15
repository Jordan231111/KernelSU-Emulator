# Guest qualification

These diagnostics exercise the real emulator and must run in a disposable registered clone with approved Shell root, the matching SUSFS module, and actual SELinux enforcing. They create their own test files and temporary mount; they do not install additional root grants. UID 19999 must be unused. The host harness refuses an occupied package UID and an instance not made by this repository's lab tools.

## Native probes

Build with the same Docker toolchain used by the project:

```sh
mkdir -p out/guest-tests/native
docker run --rm -v "$PWD:/repo:ro" -v "$PWD/out/guest-tests/native:/out" \
  ksu-emulator-toolchain:22.04 sh -c '
  for name in path_probe io_probe mount_probe path_stress; do
    aarch64-linux-gnu-gcc-9 -O2 -static -pthread -Wall -Wextra \
      /repo/tests/guest/$name.c -o /out/$name
  done'
python3 tests/guest/qualify.py --instance 6
```

Use the actual clone index. The harness tests protected path access (including `O_PATH` and target aliases), unchanged Unix modes, concurrent path/directory activity, kstat, mapped-file observations, open redirection, bind-mount hiding, fdinfo and 30 new namespaces. It writes a JSON record in `out/guest-tests/` and cold-boots the clone afterward to clear transient map rules. The simulated unprivileged processes use UID 19999, zero effective capabilities and the `untrusted_app` SELinux domain. They complement the real APK test; they do not reproduce every Android zygote/category/profile detail.

The getdents stress has eight path workers and a separate observer reading the output buffer concurrently with directory syscalls. Its result records exactly how much was tested; it is not a claim of exhaustive scheduling coverage.

Do not run a previously failed binary repeatedly after a panic. Preserve the host/guest logs and use the preserved original instance for recovery.

## Real Android application

Install Android SDK platform 35, build-tools 35.0.0 and a JDK. Override `ANDROID_SDK_ROOT`, `ANDROID_PLATFORM` and `ANDROID_BUILD_TOOLS` if needed:

```sh
bash tests/guest/build-android.sh
```

The resulting `out/guest-tests/android/probe.apk` has a local diagnostic signing key in ignored output storage. Install it only in the lab. Start `io.github.kernelsuemulator.probe/.ProbeActivity`. The app displays and writes `files/report.json` containing UI ticks, touches, sensor events, DNS, an HTTPS request to example.com, muted AudioTrack progress, and a protected-file read result.

Create the canary as root in that lab:

```sh
printf protected > /data/local/tmp/ksu-selinux-canary
chmod 644 /data/local/tmp/ksu-selinux-canary
chcon u:object_r:system_data_file:s0 /data/local/tmp/ksu-selinux-canary
```

With enforcement active, the app must report **EACCES**, while UI/input, sensors, HTTPS and audio counters advance. The file is world-readable deliberately: ordinary Unix permission bits cannot explain the denial.

For the root test, launch with the Boolean intent extra `request_root=true`. First leave the app unapproved and confirm denial. Enable **MuMu Policy Probe** in Next's Superuser screen, force-stop/relaunch with that extra, and confirm the report contains UID 0, the `ksu` domain and the expected kernel API version. Its ordinary process must still fail the canary read. Revoke the grant and repeat the denial test. Uninstall the diagnostic APK and remove the canary afterward.

For release qualification, repeat three full host stop/start cycles, query `verify --root`, `verify-hardening` and `verify-susfs`, and cold-launch the app. Check `init.svc.opengl-gc`, SurfaceFlinger and sensorservice; do not accept `sys.boot_completed=1` alone as proof that every driver client is healthy. Test your actual workloads and any added metamodule/Zygisk components separately.
