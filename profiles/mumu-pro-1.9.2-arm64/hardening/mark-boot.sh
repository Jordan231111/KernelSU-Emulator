#!/system/bin/sh
set -eu
boot=unknown
health_exit() {
    status=$?
    if [ "$status" -ne 0 ]; then
        setprop sys.ksu_mumu_policy.boot_health failed || :
        echo "Enforcing boot health failed: boot=$boot; SELinux mode was not changed."
    fi
}
trap health_exit EXIT
base=/data/adb/ksu-emulator
exec >>"$base/policy.log" 2>&1
boot=$(cat /proc/sys/kernel/random/boot_id)
setprop sys.ksu_mumu_policy.boot_health checking
echo "Enforcing boot health check: boot=$boot"
stable=0
attempt=0
last_unhealthy=none
while [ "$attempt" -lt 60 ]; do
    if [ "$(cat /sys/fs/selinux/enforce)" != 1 ]; then
        echo "Expected real SELinux enforcing: boot=$boot"
        exit 1
    fi
    healthy=1
    unhealthy=
    for service in zygote surfaceflinger vold netd nemuinit nemuinput nemu_sys_opt opengl-gc powerbtnd audioserver cameraserver media media.swcodec mediaextractor vendor.gralloc-2-0 vendor.audio-hal vendor.camera-provider-2-4 vendor.sensors-hal-2-1-multihal; do
        state=$(getprop init.svc.$service)
        if [ "$state" != running ]; then
            healthy=0
            unhealthy="$unhealthy $service=${state:-missing}"
        fi
    done
    if [ "$healthy" = 1 ]; then
        stable=$((stable+1))
    else
        stable=0
        last_unhealthy=$unhealthy
    fi
    if [ "$stable" -ge 10 ]; then
        printf '%s' "$boot" >"$base/enforcing-boot-ok.new"
        mv -f "$base/enforcing-boot-ok.new" "$base/enforcing-boot-ok"
        sync
        setprop sys.ksu_mumu_policy.boot_health passed
        echo "Enforcing boot health passed: boot=$boot"
        exit 0
    fi
    sleep 1
    attempt=$((attempt+1))
done
echo "Core services did not stabilize: boot=$boot; stable_checks=$stable/10; last_unhealthy=$last_unhealthy"
exit 1
