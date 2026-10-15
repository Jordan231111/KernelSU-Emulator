#!/system/bin/sh
set -eu
[ "$(getprop sys.ksu_mumu.susfs_ready)" = 1 ]
state=/data/adb/ksu-emulator/susfs-pending
if [ -f "$state" ] && [ "$(cat "$state")" = "$(cat /proc/sys/kernel/random/boot_id)" ]; then
    rm -f "$state"
fi
