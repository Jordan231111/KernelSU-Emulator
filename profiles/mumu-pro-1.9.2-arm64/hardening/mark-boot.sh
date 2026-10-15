#!/system/bin/sh
set -eu
[ "$(cat /sys/fs/selinux/enforce)" = 1 ]
cat /proc/sys/kernel/random/boot_id >/data/adb/ksu-emulator/enforcing-boot-ok
