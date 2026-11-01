#!/system/bin/sh
set -eu
boot=unknown
startup_exit() {
    status=$?
    if [ "$status" -ne 0 ]; then
        setprop sys.ksu_mumu_policy.enforcing_ready 0 || :
        setprop sys.ksu_mumu_policy.boot_health failed || :
        echo "SELinux enforcement startup failed: boot=$boot; enforcement was not relaxed."
    fi
}
trap startup_exit EXIT
# Enable enforcement before diagnostics or housekeeping can fail.
printf 1 >/sys/fs/selinux/enforce
[ "$(cat /sys/fs/selinux/enforce)" = 1 ]
base=/data/adb/ksu-emulator
exec >>"$base/policy.log" 2>&1
boot=$(cat /proc/sys/kernel/random/boot_id)
echo "SELinux enforcement startup: boot=$boot"
setprop sys.ksu_mumu_policy.enforcing_ready 0
setprop sys.ksu_mumu_policy.boot_health pending
# App-facing SELinux hiding is independent; retain real AVC diagnostics.
/data/adb/ksud feature set 10003 0
# Old incomplete checkpoints are not evidence of a crash and cannot veto a boot.
rm -f "$base/enforcing-pending"
setprop sys.ksu_mumu_policy.fallback ''
setprop sys.ksu_mumu_policy.enforcing_ready 1
echo "SELinux enforcing: boot=$boot; boot health is checked separately."
