# Guest qualification

These diagnostics exercise the real emulator and run on an explicitly selected instance with approved Shell root, the matching SUSFS module, and actual SELinux enforcing. They create their own test files and temporary mount; they do not install additional root grants. UID 19999 must be unused. The host harness refuses an occupied package UID.

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

Use the actual instance index. The harness tests protected path access (including `O_PATH` and target aliases), unchanged Unix modes, concurrent path/directory activity, kstat, mapped-file observations, open redirection, bind-mount hiding, fdinfo and 30 new namespaces. It writes a JSON record in `out/guest-tests/` and cold-boots the instance afterward to clear transient map rules. The simulated unprivileged processes use UID 19999, zero effective capabilities and the `untrusted_app` SELinux domain. They complement the real APK test; they do not reproduce every Android zygote/category/profile detail.

The getdents stress has eight path workers and a separate observer reading the output buffer concurrently with directory syscalls. Its result records exactly how much was tested; it is not a claim of exhaustive scheduling coverage.

Do not run a previously failed binary repeatedly after a panic. Inspect the host/guest logs and correct the failing hook before another attempt. The harness does not make backups.

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

## SELinux hiding and preference persistence

Build the diagnostic APK as above. Build `tests/guest/selinux_probe.c` with an Android NDK ARM64 compiler, for example:

```sh
mkdir -p out/guest-tests/native
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang" \
  -O2 -static -Wl,--strip-all -Wall -Wextra tests/guest/selinux_probe.c \
  -o out/guest-tests/native/selinux_probe
python3 tests/guest/qualify_selinux_hiding.py --instance 4 --leave-on
```

Use the NDK host directory appropriate to your computer and your explicit instance index. The harness tests hiding On, saved Off after cold boot, and saved On after another cold boot. It checks allowed/invalid/root contexts and an access query from a zero-capability UID 19999 process in the app_zygote domain. A pre-existing memory mapping carries results back because that domain cannot write the root shell's PTY; the tested SELinux interfaces are opened after dropping privileges. This does not grant the probe new policy permissions and does not simulate the entire app-zygote lifecycle.

The real APK separately checks UI, touch, sensors, networking, audio, denied root and the enforcement canary. It records SELinux status if accessible; some ordinary app domains are denied access to that interface. Authorized Shell root, SUSFS, vendor cleanup and all core services are checked in each case. Diagnostic files and the APK are removed afterward. `--leave-on` explicitly selects On at the end; without it, the original live value is saved again. No disk backup or clone is made.

## Video decoding and native input (required for policy changes)

Test surface-backed video decoding and MuMu's native input channel after policy changes.

With a JDK, Android SDK and `ffmpeg` installed:

```sh
python3 tests/guest/qualify_media.py --instance 0 --repeats 3
python3 tests/guest/qualify_media.py --instance 0 --size 1920x1080 --repeats 2
python3 tests/guest/qualify_media.py --instance 0 --codec c2.android.hevc.decoder --encoder libx265
python3 tests/guest/qualify_media.py --instance 0 --codec c2.android.vp9.decoder --encoder libvpx-vp9
```

Substitute the intended instance index. The harness generates its own two-second clip, uses Android's real codec service, imports graphic buffers, delivers frames to a SurfaceTexture and checks 60 frames plus end-of-stream. The client is UID 2000; the decoding service retains its real `mediaswcodec` identity. This is a media-service regression test, not a replacement for an ordinary-app isolation test. All generated classes, video clips and guest payloads are removed automatically.

Run the real APK probe separately. Click its text field in the **Mac MuMu window**, type `ksutest`, then click the report area. Confirm `nativeKeyboardText` and `touches` in `files/report.json`. Do not use `adb shell input` for this check: that bypasses the native input route. The probe checks forbidden file access once per launch to avoid flooding the audit buffer; relaunch it for a fresh isolation check.

Repeat the media and native-input checks after a cold boot and after restarting MuMu's native input/graphics helpers under enforcement. Check Binder service registration as well as process state. Do not hot-restart `nemuinit` as a normal health test: the vendor framework caches that bridge connection; use a full MuMu cold boot. Watch for a changed boot ID, service restarts and host API timeouts; an initial `running` value is insufficient. Close user apps before lifecycle testing.

For independent compiled-policy inspection on Linux with `python3-setools`:

```sh
python3 tests/policy_audit.py OLD_POLICY NEW_POLICY
```

The audit rejects changed permissive domains, type attributes or the covered ordinary-app/isolated-process rules, and prints the service-rule differences. Inspect each accepted policy serialization separately. Never publish proprietary MuMu policy binaries with the report.

## Recent Apps toolbar

After a cold boot with SELinux enforcing, click MuMu's **Recent Apps** toolbar button from Home and from Android Settings. Confirm task cards appear. Use **Clear All**, reopen Recent Apps, and confirm it is empty. Test Back, Home, and ADB input/package commands as well.

Use the native MuMu toolbar for this check. ADB's `KEYCODE_APP_SWITCH` runs in a different domain and does not exercise the bridge's command execution or service lookup.

Remove diagnostic APKs, guest probe files, temporary mounts, and generated `out/guest-tests/` output after testing.
