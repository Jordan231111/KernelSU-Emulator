#!/system/bin/sh
# Preserve MuMu's platform API without its broken legacy-su boot receiver.
set -eu
exec >>/data/adb/ksu-emulator/platform-service.log 2>&1
component=com.netease.nemu_vapi_android.nemu/com.netease.nemu_vapi_android.receiver.LaunchReceiver
setprop sys.ksu_mumu.platform_ready 0
# Binder's shell-command API passes these descriptors to system_server.
# Do not pass the private root log file as its output descriptor.
attempt=0
while [ "$attempt" -lt 5 ]; do
    if /system/bin/pm disable --user 0 "$component" </dev/null >/dev/null 2>&1 &&
       /system/bin/am startservice --user 0 -n com.netease.nemu_vapi_android.nemu/com.netease.nemu_vapi_android.service.ApiService </dev/null >/dev/null 2>&1; then
        setprop sys.ksu_mumu.platform_ready 1
        echo 'MuMu platform API started without the vendor-su receiver.'
        exit 0
    fi
    sleep 1
    attempt=$((attempt+1))
done
echo 'MuMu platform API startup failed.'
exit 1
