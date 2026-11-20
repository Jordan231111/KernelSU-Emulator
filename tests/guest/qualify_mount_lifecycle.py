#!/usr/bin/env python3
"""Whole-filesystem binds, automatic tagging, first-read FD IDs, and teardown."""
import argparse
import json
import re
import shlex
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT
from ksu_emulator.mumu import MuMu


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    parser.add_argument("--capacity", type=int, default=1100,
                        help="Simultaneous mounts; must exceed the upstream 1024-entry ID cache")
    args = parser.parse_args()
    if args.capacity <= 1024 or args.capacity > 4096:
        parser.error("--capacity must be between 1025 and 4096")
    mumu = MuMu()
    adb = mumu.connect(args.instance)
    assert adb.su("cat /sys/fs/selinux/enforce") == "1"
    assert "uid:19999" not in adb.shell("pm list packages -U")
    base = "/data/local/tmp/ksu-mount-life-" + uuid.uuid4().hex[:10]
    client = "/data/adb/modules/mumu_susfs/susfs-sc"
    probe = f"{base}/probe {base}/mount/local/tmp/{base.rsplit('/', 1)[1]}/canary {base}/mount /data"
    report = {"instance": args.instance, "expected": {
        "automatic": "KSU bind hidden without a prefix, original /data visible",
        "registered": "explicit registration does not hide the original filesystem",
        "namespace": "FD mount ID resolves in the new namespace even when read first",
        "root": "both mounts visible to root",
        "toggle": "visibility off/on leaves creation and teardown tracking working",
        "teardown": "repeated mounts do not exhaust ID records or leave stale translations",
        "capacity": "FD IDs remain resolvable when simultaneous mounts exceed the ID cache"}}
    try:
        adb.shell("mkdir -m 0755 " + base)
        adb.push(ROOT / "out/guest-tests/native/mount_lifecycle_probe", base + "/probe")
        adb.su(f"chmod 755 {base}/probe; chcon u:object_r:system_file:s0 {base} {base}/probe; "
               f"echo retained > {base}/canary; chmod 644 {base}/canary; "
               f"chcon u:object_r:system_file:s0 {base}/canary")
        command = f"""set -e
mkdir {base}/mount
mount --bind /data {base}/mount
mounted=0
cleanup() {{
    while [ $mounted -gt 0 ]; do
        mounted=$((mounted-1))
        umount {base}/capacity/$mounted || :
    done
    umount {base}/mount 2>/dev/null || :
    echo "del {base}/" >/proc/susfs_hide_mounts
    {client} 0x55561 0100000000000000 >/dev/null
}}
trap cleanup EXIT
echo AUTO
{probe} app
echo ROOT
{probe}
echo 'add {base}/' >/proc/susfs_hide_mounts
echo REGISTERED
{probe} app
echo ORIGINAL
{base}/probe {base}/canary {base}/mount /data app
echo NAMESPACES
i=0; while [ $i -lt 120 ]; do {probe} app namespace; i=$((i+1)); done
echo OFF
{client} 0x55561 0000000000000000 >/dev/null
{probe} app
echo ON
{client} 0x55561 0100000000000000 >/dev/null
{probe} app
umount {base}/mount
echo REUSE
i=0; while [ $i -lt 200 ]; do
    mount --bind /data {base}/mount
    {probe} app
    umount {base}/mount
    i=$((i+1))
done
mkdir {base}/capacity
while [ $mounted -lt {args.capacity} ]; do
    mkdir {base}/capacity/$mounted
    mount --bind /data {base}/capacity/$mounted
    mounted=$((mounted+1))
done
echo CAPACITY
{base}/probe {base}/capacity/{args.capacity-1}/local/tmp/{base.rsplit('/', 1)[1]}/canary {base}/capacity/{args.capacity-1} /data app
echo CAPACITY_STATS
cat /sys/module/susfs_guard_lkm/parameters/mount_stat
"""
        # Isolate both mounts and propagation before allocating the fixture.
        output = adb.shell("su -c " + shlex.quote(base + "/probe --private-namespace /system/bin/sh -c " + shlex.quote(command)), timeout=240)
        current = None
        sections = {}
        for line in output.splitlines():
            if line in {"AUTO", "ROOT", "REGISTERED", "ORIGINAL", "NAMESPACES", "OFF", "ON", "REUSE", "CAPACITY"}:
                current = line
                sections[current] = []
            elif line.startswith("{") and current:
                sections[current].append(json.loads(line))
        report["observed"] = sections
        report["simultaneous_mounts"] = args.capacity
        report["capacity_stats"] = output.split("CAPACITY_STATS\n", 1)[1]
        assert re.search(r"idmap:.*full=[1-9]", report["capacity_stats"]), report["capacity_stats"]
        for name, rows in sections.items():
            assert rows, name
            for row in rows:
                assert row["original_visible"] == 1, (name, row)
                assert row["fd_mount_visible"], (name, row)
                assert row["target_visible"] == (1 if name in {"ROOT", "OFF"} else 0), (name, row)
        assert len(sections["NAMESPACES"]) == 120 and len(sections["REUSE"]) == 200
        report["counters"] = adb.su("cat /sys/module/susfs_guard_lkm/parameters/mumu_mount_stats")
        assert not re.search(r"(?:allocation_failures|attach_missed|clone_missed)=[1-9]", report["counters"]), report["counters"]
        assert "active=1" in report["counters"]
        report["build_hashes"] = adb.su("sha256sum /system/etc/ksu-emulator/kernelsu.ko /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko")
        report["passed"] = True
    except Exception as error:
        report.update(passed=False, error=str(error))
        raise
    finally:
        path = ROOT / "out/audit/mount-lifecycle.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
        adb.su("rm -rf " + base, check=False)
        print(path)


if __name__ == "__main__":
    main()
