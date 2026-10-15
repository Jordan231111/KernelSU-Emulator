#!/system/bin/sh
mkdir -p /data/adb/ksu-emulator
exec >>/data/adb/ksu-emulator/policy.log 2>&1
set -eu
mount -o remount,rw /
for item in / /bin /etc /lib /product /system_ext /vendor; do
    [ ! -e "$item" ] && [ ! -L "$item" ] || chcon -h u:object_r:rootfs:s0 "$item"
done
for item in /odm /odm/*; do
    [ ! -e "$item" ] && [ ! -L "$item" ] || chcon -h u:object_r:vendor_file:s0 "$item"
done
mount -o remount,ro /
# MuMu rewrites normal /system paths for some processes. PID 1's root
# reaches the private writable system mount and the actual vendor files.
find /proc/1/root/system/etc/mumu-configs/java_patch /proc/1/root/system/etc/mumu-configs/shared_libs -exec ls -Zd {} \; | awk '$1 != "u:object_r:system_file:s0" { bad=1; print "Unexpected system label: " $0 } END { exit bad }'
[ "$(ls -Zd /proc/1/root/system/etc/mumu-configs/currentApp | cut -d ' ' -f 1)" = u:object_r:mumu_runtime_config_file:s0 ]
for item in /data/system/etc/mumu-configs /data/tombstones/app; do
    if [ -d "$item" ]; then restorecon -RF "$item"; fi
done
restorecon -F /dev/vaddress
restorecon -F /mnt/shared
setprop sys.ksu_mumu_policy.labels_ready 1
