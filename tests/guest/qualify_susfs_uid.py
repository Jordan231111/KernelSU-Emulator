#!/usr/bin/env python3
"""Test SUSFS 2.4 UID filters against our own installed diagnostic package."""
import argparse
import json
import re
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT, Error, save_json
from ksu_emulator.mumu import MuMu


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    args = parser.parse_args()
    mumu = MuMu()
    adb = mumu.connect(args.instance)
    package = "io.github.kernelsuemulator.probe"
    if adb.shell("pm path " + package, check=False):
        raise Error("The diagnostic package is already installed")
    if "uid:19999" in adb.shell("pm list packages -U"):
        raise Error("Diagnostic UID 19999 is occupied")
    base = "/data/local/tmp/ksu-uid-" + uuid.uuid4().hex[:12]
    cli = "/data/adb/modules/mumu_susfs/ksu_susfs"
    report = {"boot_id": adb.su("cat /proc/sys/kernel/random/boot_id"), "cases": {},
              "build_hashes": adb.su("sha256sum /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko")}
    output = ROOT / "out/audit/susfs-uid.json"
    installed = False
    pid = None

    def case(name, expected, observed, passed):
        report["cases"][name] = dict(expected=expected, observed=observed, passed=passed)
        save_json(output, report)
        if not passed:
            raise Error(name + " did not match its expected result")

    try:
        adb.shell("mkdir -m 0755 " + base)
        for name in ("state_probe", "path_probe"):
            adb.push(ROOT / "out/guest-tests/native" / name, base + "/" + name)
        adb.su(f"chmod 755 {base}/*; chcon u:object_r:system_file:s0 {base} {base}/*; "
               f"echo hidden > {base}/hidden; chmod 644 {base}/hidden; chcon u:object_r:system_file:s0 {base}/hidden")
        adb.call("install", ROOT / "out/guest-tests/android/probe.apk", timeout=120)
        installed = True
        uid = int(re.search(r"userId=(\d+)", adb.shell("dumpsys package " + package)).group(1))
        report["diagnostic_uid"] = uid
        pid = adb.su(f"nohup {base}/state_probe root hold {uid} >{base}/hold.log 2>&1 </dev/null & echo $!")
        if not pid.isdigit():
            raise Error("Cannot identify the diagnostic holder process")
        before = adb.su(f"{base}/state_probe app priority {uid}")
        adb.su(f"{cli} set_priority_uid_filter {package}")
        after = adb.su(f"{base}/state_probe app priority {uid}")
        root = adb.su(f"{base}/state_probe root priority {uid}")
        own = adb.su(f"{base}/state_probe app priority 0")
        case("priority", "All four explicit other-UID priority APIs return ESRCH; root and who=0 retain access",
             dict(before=before, after=after, root=root, own=own),
             "getpriority=0 errno=0" in before and after.count("=-1 errno=3") == 4
             and "getpriority=0 errno=0" in root and "getpriority=0 errno=0" in own)
        adb.su(f"{cli} add_sus_path {base}/hidden")
        broad = adb.su(f"{base}/path_probe {base}/hidden app")
        configured = adb.su(f"{base}/state_probe root uid_filter 0x55554 {package}")
        unselected = adb.su(f"{base}/path_probe {base}/hidden app")
        selected = adb.su(f"{base}/path_probe {base}/hidden app {uid}")
        case("path_selection", "Default covers all apps; a configured list hides from the selected UID and preserves unselected access",
             dict(default=broad, command=configured, unselected=unselected, selected=selected),
             "stat=-1 errno=2" in broad and "stat=0 errno=0" in unselected and "dirent=1" in unselected
             and "stat=-1 errno=2" in selected and "dirent=0" in selected)
        bad = adb.su(f"{base}/state_probe root uid_filter 0x55554 ../../invalid", check=False)
        still = adb.su(f"{base}/path_probe {base}/hidden app {uid}")
        case("invalid_configuration", "EINVAL without replacing the working filter", dict(command=bad, selected=still),
             "command_error=-22" in bad and "stat=-1 errno=2" in still)
        # Removing the test package changes the public package registry. The next
        # app UID transition refreshes the filter before the probe's first syscall.
        adb.call("uninstall", package, timeout=120)
        installed = False
        refreshed = adb.su(f"{base}/state_probe app priority {uid}")
        case("package_removal", "The stale UID is removed while our holder process still exists", refreshed,
             "getpriority=0 errno=0" in refreshed)
        report["passed"] = True
    except Exception as exc:
        report.update(passed=False, error=str(exc))
        raise
    finally:
        save_json(output, report)
        try:
            if pid:
                adb.su("kill " + pid, check=False)
            if installed:
                adb.call("uninstall", package, timeout=120, check=False)
            adb.su(f"echo 'del {base}/hidden' > /proc/susfs_path; rm -rf {base}", check=False)
        except Error:
            pass
        mumu.stop(args.instance)
        adb = mumu.start(args.instance)
        adb.su("rm -rf " + base, check=False)
        print(output)


if __name__ == "__main__":
    main()
