#!/usr/bin/env python3
"""Measure less common SUSFS surfaces using only disposable diagnostic files."""
import argparse
import json
import re
import shlex
import sys
import time
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
    if "uid:19999" in adb.shell("pm list packages -U"):
        raise Error("Diagnostic UID 19999 is occupied")
    base = "/data/local/tmp/ksu-edge-" + uuid.uuid4().hex[:12]
    cli = "/data/adb/modules/mumu_susfs/ksu_susfs"
    output = ROOT / "out/audit/susfs-edges.json"
    report = {"boot_id": adb.su("cat /proc/sys/kernel/random/boot_id"), "cases": {},
              "build_hashes": adb.su("sha256sum /system/etc/ksu-emulator/kernelsu.ko /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko")}

    def record(name, expected, observed, passed, gap=False):
        report["cases"][name] = dict(expected=expected, observed=observed, passed=passed, canonical_gap=gap)
        save_json(output, report)

    def tool(*args):
        return adb.su(" ".join(map(shlex.quote, (cli, *args))))

    try:
        adb.shell("mkdir -m 0755 " + base)
        for name in ("io_probe", "path_probe", "state_probe"):
            adb.push(ROOT / "out/guest-tests/native" / name, base + "/" + name)
        adb.su(f"chmod 755 {base}/*; chcon u:object_r:system_file:s0 {base} {base}/*; "
               f"dd if=/dev/zero of={base}/map bs=1048576 count=8; chmod 644 {base}/map; chcon u:object_r:system_file:s0 {base}/map")
        before = adb.su(f"{base}/io_probe rollup {base}/map app")
        tool("add_sus_map", base + "/map")
        after = adb.su(f"{base}/io_probe rollup {base}/map app")
        root = adb.su(f"{base}/io_probe rollup {base}/map")
        deltas = [int(re.search(r"delta_kb=(-?\d+)", x).group(1)) for x in (before, after, root)]
        record("smaps_rollup", "An 8 MiB resident file adds >=8192 KiB before registration/root, <512 KiB for filtered app",
               dict(before=before, after=after, root=root), deltas[0] >= 8192 and deltas[1] < 512 and deltas[2] >= 8192)
        adb.su(f"echo 'del {base}/map' > /proc/susfs_map")
        for mode in ("update_sus_kstat", "update_sus_kstat_full_clone"):
            path = base + "/" + mode
            adb.su(f"printf original > {path}; chmod 644 {path}; chcon u:object_r:system_file:s0 {path}")
            original = adb.su(f"stat -c '%i %s' {path}").split()
            tool("add_sus_kstat", path)
            adb.su(f"printf longer-replacement > {path}.new; chmod 644 {path}.new; chcon u:object_r:system_file:s0 {path}.new; mv {path}.new {path}")
            tool(mode, path)
            observed = adb.su(f"{base}/path_probe {path} app")
            size = "18" if mode == "update_sus_kstat" else original[1]
            record(mode, f"Original inode {original[0]} and size {size}", observed,
                   f"ino={original[0]} size={size}" in observed)
            adb.su(f"echo 'del {path}' > /proc/susfs_kstat")
        loop = base + "/loop"
        adb.su(f"echo first > {loop}; chmod 644 {loop}; chcon u:object_r:system_file:s0 {loop}")
        tool("add_sus_path_loop", loop)
        old = adb.su(f"{base}/path_probe {loop} app")
        adb.su(f"echo replacement > {loop}.new; chmod 644 {loop}.new; chcon u:object_r:system_file:s0 {loop}.new; mv {loop}.new {loop}")
        time.sleep(5)
        new = adb.su(f"{base}/path_probe {loop} app")
        record("loop_replacement", "Canonical loop rules track a replacement inode on later app specialization",
               dict(initial=old, replacement_after_5s=new), "stat=-1 errno=2" in new)
        adb.su(f"echo 'del {loop}' > /proc/susfs_path")
        # The object is our own file; no unrelated AVC records are retained.
        avc_file = base + "/avc-probe"
        adb.su(f"echo denied > {avc_file}; chmod 644 {avc_file}; chcon u:r:ksu:s0 {avc_file}")
        avc = []
        # Avoid Android's audit rate limit after the preceding filesystem tests.
        time.sleep(5)
        for enabled in ("0", "1", "0", "1", "0"):
            tool("enable_avc_log_spoofing", enabled)
            before = adb.su("cat /proc/susfs_avc_spoof")
            time.sleep(2)
            observation = adb.su(f"{base}/path_probe {avc_file} app")
            after = adb.su("cat /proc/susfs_avc_spoof")
            avc.append(dict(enabled=enabled, before=before, after=after, access=observation))
        logs = adb.su("dmesg | grep -F 'name=\"avc-probe\"'", check=False)
        hits = [int(re.search(r"hits=(\d+)", x["after"]).group(1)) for x in avc]
        record("avc_spoof", "On rewrites controlled ksu AVC contexts; Off restores them; access stays denied and enforcing stays 1",
               dict(cycles=avc, diagnostic_log=logs, enforcing=adb.su("cat /sys/fs/selinux/enforce")),
               hits[1] > hits[0] and hits[3] > hits[2] and all("open=-1 errno=13" in x["access"] for x in avc)
               and "tcontext=u:r:priv_app:" in logs)
        overlay = adb.su(
            f"set -e; mkdir {base}/lower {base}/upper {base}/work {base}/merged; "
            f"printf original > {base}/lower/shared; "
            f"touch {base}/lower/lower-only {base}/upper/upper-only; "
            f"chmod 644 {base}/lower/* {base}/upper/*; "
            f"chcon u:object_r:system_file:s0 {base}/lower/* {base}/upper/*; "
            f"chcon u:object_r:system_file:s0 {base}/lower {base}/upper {base}/work {base}/merged; "
            f"mount -t overlay overlay -o lowerdir={base}/lower,upperdir={base}/upper,workdir={base}/work {base}/merged; "
            f"trap 'umount {base}/merged' EXIT; printf longer-replacement > {base}/merged/shared; "
            f"echo LOWER; {base}/state_probe app statfs {base}/lower; "
            f"echo OVERLAY; {base}/state_probe app statfs {base}/merged; "
            f"echo APP_STAT; {base}/path_probe {base}/merged/shared app; "
            f"echo ROOT_STAT; {base}/path_probe {base}/merged/shared; "
            f"echo UPPER_LIST; {base}/path_probe {base}/merged/upper-only app; "
            f"echo ROOT_FS; {base}/state_probe root statfs {base}/merged")
        record("overlay_statfs", "App sees lower ext4 type and its private read-only mount flags, original size 8 after copy-up; upper-only name omitted; root retains size 18 and overlay magic",
               overlay, "type=ef53 flags=420" in overlay and "type=ef53 flags=421" in overlay and "type=794c7630" in overlay
               and "size=8 " in overlay.split("ROOT_STAT")[0] and "size=18 " in overlay.split("ROOT_STAT")[1]
               and "dirent=0" in overlay.split("UPPER_LIST")[1])
        report["implemented_checks_passed"] = all(v["passed"] for v in report["cases"].values() if not v["canonical_gap"])
        if not report["implemented_checks_passed"]:
            raise Error("An implemented SUSFS feature failed its controlled check")
    except Exception as exc:
        report["error"] = str(exc)
        raise
    finally:
        save_json(output, report)
        try:
            adb.su(f"echo 0 > /proc/susfs_avc_spoof; rm -rf {base}", check=False)
        except Error:
            pass
        mumu.stop(args.instance)
        adb = mumu.start(args.instance)
        adb.su("rm -rf " + base, check=False)
        print(output)


if __name__ == "__main__":
    main()
