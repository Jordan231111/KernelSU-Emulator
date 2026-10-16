#!/system/bin/sh
set -eu
base=/data/adb/ksu-emulator
exec >>"$base/policy.log" 2>&1
boot=$(cat /proc/sys/kernel/random/boot_id)
old=$(cat /sys/fs/selinux/enforce)
/data/adb/ksud feature set 4 0
/data/adb/ksud feature set 10003 0
if [ -f "$base/enforcing-pending" ] && [ "$(cat "$base/enforcing-pending")" != "$boot" ]; then
    echo 'A previous enforcing boot did not complete; preserving permissive recovery mode.'
    setprop sys.ksu_mumu_policy.fallback previous-boot
    exit 1
fi
printf '%s' "$boot" >"$base/enforcing-pending"
sync
printf 1 >/sys/fs/selinux/enforce
[ "$(cat /sys/fs/selinux/enforce)" = 1 ]
setprop sys.ksu_mumu_policy.enforcing_ready 1
i=0
while [ "$i" -lt 90 ]; do
    if [ -f "$base/enforcing-boot-ok" ] && [ "$(cat "$base/enforcing-boot-ok")" = "$boot" ]; then
        rm -f "$base/enforcing-pending"
        sync
        echo 'Enforcing boot completed; recovery watchdog disarmed.'
        exit 0
    fi
    sleep 1
    i=$((i+1))
done
printf '%s' "$old" >/sys/fs/selinux/enforce
setprop sys.ksu_mumu_policy.enforcing_ready 0
setprop sys.ksu_mumu_policy.fallback timeout
echo 'Enforcing boot timed out; original mode restored.'
exit 1
