#!/system/bin/sh
set -eu
boot=$(cat /proc/sys/kernel/random/boot_id)
stable=0
attempt=0
while [ "$attempt" -lt 60 ]; do
    [ "$(cat /sys/fs/selinux/enforce)" = 1 ] || exit 1
    healthy=1
    for service in zygote surfaceflinger vold netd nemuinit nemuinput nemu_sys_opt opengl-gc powerbtnd audioserver cameraserver media media.swcodec mediaextractor vendor.gralloc-2-0 vendor.audio-hal vendor.camera-provider-2-4 vendor.sensors-hal-2-1-multihal; do
        [ "$(getprop init.svc.$service)" = running ] || healthy=0
    done
    if [ "$healthy" = 1 ]; then stable=$((stable+1)); else stable=0; fi
    if [ "$stable" -ge 10 ]; then
        printf '%s' "$boot" >/data/adb/ksu-emulator/enforcing-boot-ok
        sync
        exit 0
    fi
    sleep 1
    attempt=$((attempt+1))
done
exit 1
