#!/usr/bin/env python3
"""Test the saved SELinux-hide preference, actual isolation and observable hiding.

Uses only its own diagnostic APK/files; changes the selected preference and cold
boots the explicit instance. Leaves hiding enabled as requested by --leave-on,
otherwise restores the original preference value. No disk copies are created.
"""
import argparse
import json
import re
import shlex
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT, Error
from ksu_emulator.hardening import wait_hardening
from ksu_emulator.install import verify
from ksu_emulator.mumu import MuMu
from ksu_emulator.susfs import verify_susfs
from ksu_emulator.vendor import verify_vendor_cleanup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    parser.add_argument("--leave-on", action="store_true")
    args = parser.parse_args()
    mumu = MuMu()
    adb = mumu.connect(args.instance)
    profile = "mumu-pro-1.9.2-arm64"
    package = "io.github.kernelsuemulator.probe"
    if adb.shell("pm path " + package, check=False):
        raise Error("Remove an existing diagnostic APK before qualification")
    if "uid:19999" in adb.shell("pm list packages -U"):
        raise Error("Diagnostic UID 19999 is occupied")
    original = int(re.search(r"^Value: ([01])$", adb.su("/data/adb/ksud feature get 4"), re.M).group(1))
    final_value = 1 if args.leave_on else original
    stage = "/data/local/tmp/ksu-hide-qa-" + uuid.uuid4().hex
    report = {"instance": args.instance, "cases": []}
    output = ROOT / "out" / "selinux-hiding-qualification.json"
    installed = False
    try:
        adb.shell("mkdir -m 0700 " + stage)
        adb.push(ROOT / "out/guest-tests/native/selinux_probe", stage + "/probe")
        adb.su(f"chmod 755 {stage}/probe; chcon u:object_r:system_file:s0 {stage}/probe")
        adb.call("install", ROOT / "out/guest-tests/android/probe.apk", timeout=120)
        installed = True
        # The first On case is the current boot. Subsequent cases explicitly
        # exercise saved Off and saved On across full host stop/start cycles.
        for position, value in enumerate((1, 0, 1)):
            adb.su(f"/data/adb/ksud feature set 4 {value}; /data/adb/ksud feature save")
            if position:
                mumu.stop(args.instance)
                adb = mumu.start(args.instance)
            hardening = wait_hardening(mumu, args.instance, profile)
            assert hardening["verified"] and hardening["selinux_hiding_enabled"] is bool(value)
            assert hardening["saved_selinux_hiding_enabled"] is bool(value)
            observations = {}
            for mode in ("app", "root"):
                adb.su(f"{stage}/probe {mode} {stage}/report")
                observations[mode] = adb.bytes("su -c " + shlex.quote("cat " + stage + "/report")).split(b"\0", 1)[0].decode()
            app, root = observations["app"], observations["root"]
            assert "uid=19999 caps=0000000000000000 context=u:r:app_zygote:s0" in app
            assert "stock accepted=1" in app and "nonexistent accepted=0 errno=22" in app
            assert "root_context accepted=1" in root and "access response=ffffffff" in root
            if value:
                assert "root_context accepted=0 errno=22" in app and "access response=0 " in app
                assert "sequence=0 enforcing=1 policyload=0" in app
            else:
                assert "root_context accepted=1" in app and "access response=ffffffff" in app
            adb.su("printf protected > /data/local/tmp/ksu-selinux-canary; chmod 644 /data/local/tmp/ksu-selinux-canary; "
                   "chcon u:object_r:system_data_file:s0 /data/local/tmp/ksu-selinux-canary")
            adb.shell("am force-stop " + package)
            adb.shell("am start -W -n " + package + "/.ProbeActivity --ez request_root true")
            adb.shell("input tap 700 600")
            time.sleep(15)
            ordinary = json.loads(adb.su("cat /data/user/0/" + package + "/files/report.json"))
            print("Ordinary-app observations: " + json.dumps(ordinary), flush=True)
            assert "EACCES" in ordinary["protectedRead"] and "uid=0" not in ordinary["root"]
            assert ordinary["uiTicks"] >= 15 and ordinary["sensorEvents"] >= 15
            assert ordinary["audioFrames"] > 20000 and ordinary["https"] == "HTTP 200" and ordinary["touches"] > 0
            if "selinuxStatus" in ordinary:
                status = ordinary["selinuxStatus"]
                assert status["enforcing"] == 1
                if value:
                    assert status["sequence"] == 0 and status["policyload"] == 0
            else:
                # Some ordinary app domains cannot open this interface. The
                # app_zygote-domain probe above verifies its accessible view.
                assert "EACCES" in ordinary.get("selinuxStatusError", ""), ordinary
            adb.shell("am force-stop " + package)
            core = verify(mumu, args.instance, root=True)
            susfs, vendor = verify_susfs(mumu, args.instance), verify_vendor_cleanup(mumu, args.instance)
            assert core["persistent_install_ready"] and susfs["verified"] and vendor["verified"]
            case = {"enabled": bool(value), "cold_boot": bool(position), "hardening": hardening,
                    "native": observations, "ordinary_app": ordinary, "root_verified": True,
                    "susfs_verified": True, "vendor_cleanup_verified": True}
            report["cases"].append(case)
            output.write_text(json.dumps(report, indent=2) + "\n")
            print(f"Hiding={value}: native observations, real app, enforcement and root passed", flush=True)
        report["passed"] = True
        output.write_text(json.dumps(report, indent=2) + "\n")
    finally:
        adb = mumu.connect(args.instance)
        if installed:
            adb.call("uninstall", package, timeout=120, check=False)
        adb.su(f"rm -rf {stage}; rm -f /data/local/tmp/ksu-selinux-canary; "
               f"/data/adb/ksud feature set 4 {final_value}; /data/adb/ksud feature save")
    print(output)


if __name__ == "__main__":
    main()
