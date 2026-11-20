#!/usr/bin/env python3
"""Destructive only to its own test files; requires an explicit instance."""
import argparse
import json
import re
import shlex
import struct
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT
from ksu_emulator.mumu import MuMu


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    args = parser.parse_args()
    mumu = MuMu()
    adb = mumu.connect(args.instance)
    assert adb.su("cat /sys/fs/selinux/enforce") == "1", "Requires actual enforcement"
    assert adb.su("/data/adb/ksud susfs version") == "v2.4.0"
    assert "uid:19999" not in adb.shell("pm list packages -U"), "Test UID is occupied"
    base = "/data/local/tmp/ksu-qa-" + uuid.uuid4().hex[:12]
    output = ROOT / "out/guest-tests" / (str(args.instance) + "-" + base.rsplit("-", 1)[-1] + ".json")
    report = {"instance": args.instance, "kernel_enforcing": True, "paths": {},
              "boot_id": adb.su("cat /proc/sys/kernel/random/boot_id"),
              "build_hashes": adb.su("sha256sum /system/etc/ksu-emulator/kernelsu.ko /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko"),
              "expected": {"path": "app stat/open/O_PATH return ENOENT and listing omits the name; root still sees it",
                           "permissions": "644 and 600 remain unchanged",
                           "kstat": "app sees inode 12345 and size 4242; root sees original metadata",
                           "map": "app maps/smaps/pagemap/mem hide the registered mapping; root sees it",
                           "redirect": "app reads replacement; root reads original",
                           "mount": "app mountinfo omits the bind mount in the original and 30 new namespaces"}}
    client = "/data/adb/modules/mumu_susfs/susfs-sc"
    hidden_paths = []

    def command(node, text):
        return adb.su("echo " + shlex.quote(text) + " > /proc/" + node)

    def path_probe(name, app=True):
        return adb.su(base + "/path_probe " + base + "/" + name + (" app" if app else ""))

    try:
        adb.shell("mkdir -m 0755 " + base)
        for name in ("path_probe", "io_probe", "mount_probe", "path_stress", "kstat_stress"):
            adb.push(ROOT / "out/guest-tests/native" / name, base + "/" + name)
        adb.su(f"chmod 755 {base}/*; chcon u:object_r:system_file:s0 {base} {base}/*; "
               f"echo public > {base}/public; echo private > {base}/private; echo metadata > {base}/metadata; "
               f"chmod 644 {base}/public {base}/metadata; chmod 600 {base}/private; "
               f"chcon u:object_r:system_file:s0 {base}/public {base}/private {base}/metadata")
        for name in ("public", "private"):
            before = path_probe(name)
            command("susfs_path", "add " + base + "/" + name)
            hidden_paths.append(base + "/" + name)
            after, root = path_probe(name), path_probe(name, False)
            assert all(x in after for x in ("stat=-1 errno=2", "open=-1 errno=2", "opath=-1 errno=2", "dirent=0")), after
            assert "stat=0 errno=0" in root and "dirent=1" in root
            report["paths"][name] = {"before": before, "after": after, "root": root}
        report["preserved_modes"] = adb.su(f"stat -c %a {base}/public {base}/private")
        assert report["preserved_modes"] == "644\n600"
        # Inode-based rules must also apply through another name for that inode.
        adb.su(f"ln {base}/public {base}/hardlink; ln -s {base}/public {base}/symlink")
        for name in ("hardlink", "symlink"):
            result = path_probe(name)
            assert "open=-1 errno=2" in result and "opath=-1 errno=2" in result, result
            if name == "hardlink":
                assert "dirent=0" in result, result
            report["paths"][name] = result
        adb.su(f"echo own > {base}/owned; chmod 644 {base}/owned; "
               f"chown 19999:19999 {base}/owned; chcon u:object_r:system_file:s0 {base}/owned")
        command("susfs_path", "add " + base + "/owned")
        hidden_paths.append(base + "/owned")
        owned = path_probe("owned")
        assert "stat=0 errno=0" in owned and "dirent=1" in owned, owned
        report["paths"]["caller_owned"] = owned
        marker = base + "/ksu_hidden_probe_marker"
        adb.su(f"echo race > {marker}; chmod 644 {marker}; chcon u:object_r:system_file:s0 {marker}")
        command("susfs_path", "add " + marker)
        hidden_paths.append(marker)
        report["concurrency"] = adb.su(base + "/path_stress " + base + " " + marker)
        assert "leaked_names=0 failures=0" in report["concurrency"]
        command("susfs_kstat", f"add_sus_kstat_statically {base}/metadata 12345 2049 1 4242 100 0 100 0 100 0 8 4096")
        report["kstat_app"], report["kstat_root"] = path_probe("metadata"), path_probe("metadata", False)
        assert "ino=12345 size=4242" in report["kstat_app"]
        assert "ino=12345 size=4242" not in report["kstat_root"]
        original_inode = re.search(r"ino=(\d+)", report["kstat_root"]).group(1)
        report["kstat_concurrency"] = adb.su(f"{base}/kstat_stress {base}/metadata {original_inode}")
        assert "original_inode_observations=0 failures=0" in report["kstat_concurrency"]
        command("susfs_kstat", "del " + base + "/metadata")
        adb.su(f"dd if=/dev/zero of={base}/maps.bin bs=4096 count=1; chmod 644 {base}/maps.bin; chcon u:object_r:system_file:s0 {base}/maps.bin")
        probe = base + "/io_probe map " + base + "/maps.bin"
        report["map_before"] = adb.su(probe + " app")
        payload = struct.pack("<256si", (base + "/maps.bin").encode(), 126).hex()
        adb.su(client + " 0x60020 " + payload)
        report["map_after"], report["map_root"] = adb.su(probe + " app"), adb.su(probe)
        assert "map_visible=1" in report["map_before"] and "map_visible=0" in report["map_after"]
        assert "map_visible=1" in report["map_root"]
        assert "smaps_visible=0" in report["map_after"] and "entry=0000000000000000" in report["map_after"]
        assert "mem_bytes=-1" in report["map_after"] and "mem_bytes=1" in report["map_root"]
        assert "map_files_visible=0" in report["map_after"], report["map_after"]
        assert "map_files_readlink=-1 errno=2" in report["map_after"], report["map_after"]
        adb.su(f"echo original > {base}/original; echo replacement > {base}/replacement; chmod 644 {base}/original {base}/replacement; chcon u:object_r:system_file:s0 {base}/original {base}/replacement")
        command("susfs_open_redirect", f"add_open_redirect {base}/original {base}/replacement 2")
        report["redirect_app"] = adb.su(f"{base}/io_probe read {base}/original app")
        report["redirect_root"] = adb.su(f"{base}/io_probe read {base}/original")
        assert "content=replacement" in report["redirect_app"] and "content=original" in report["redirect_root"]
        app_inode = re.search(r"fd_ino=(\d+)", report["redirect_app"]).group(1)
        root_inode = re.search(r"fd_ino=(\d+)", report["redirect_root"]).group(1)
        assert app_inode == root_inode, report["redirect_app"]
        command("susfs_open_redirect", "del " + base + "/original")
        probe = f"{base}/mount_probe {base}/mount/file"
        # su sessions use separate mount namespaces. Keep creation, observations
        # and cleanup in ONE root shell so every child sees the same mount.
        mount_output = adb.su(
            f"set -e; mkdir {base}/mount {base}/mountsource; echo mount > {base}/mountsource/file; "
            f"chmod 755 {base}/mount {base}/mountsource; chmod 644 {base}/mountsource/file; "
            f"chcon u:object_r:system_file:s0 {base}/mount {base}/mountsource {base}/mountsource/file; "
            f"mount --bind {base}/mountsource {base}/mount; trap 'umount {base}/mount' EXIT; "
            f"{client} 0x55561 0000000000000000 >/dev/null; echo BEFORE; {probe} app; "
            f"{client} 0x55561 0100000000000000 >/dev/null; echo 'add {base}/' > /proc/susfs_hide_mounts; "
            f"echo AFTER; {probe} app; echo ROOT; {probe}; echo NAMESPACES; "
            f"i=0; while [ $i -lt 30 ]; do {probe} app namespace; i=$((i+1)); done; "
            f"echo 'del {base}/' > /proc/susfs_hide_mounts")
        report["mount_before"], rest = mount_output.split("AFTER\n", 1)
        report["mount_after"], rest = rest.split("ROOT\n", 1)
        report["mount_root"], namespaces = rest.split("NAMESPACES\n", 1)
        assert "mount_visible=1" in report["mount_before"] and "mount_visible=0" in report["mount_after"], report
        assert "mount_visible=1" in report["mount_root"]
        assert namespaces.count("mount_visible=0") == 30, namespaces
        report["new_namespaces"] = 30
        report["path_counters"] = adb.su("cat /sys/module/susfs_guard_lkm/parameters/legacy_path_stats")
        assert not re.search(r"(?:open|perm)_missed=[1-9]|fill_missed=(?!0/0/0)", report["path_counters"])
        assert adb.su("cat /sys/fs/selinux/enforce") == "1"
        report["passed"] = True
    except Exception as exc:
        report.update(passed=False, error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        # Preserve the failure even when a broken kernel disconnects ADB.
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        for path in hidden_paths:
            try:
                adb.su("echo " + shlex.quote("del " + path) + " > /proc/susfs_path", check=False)
            except Exception:
                break
        try:
            adb.su("echo " + shlex.quote("del " + base + "/") + " > /proc/susfs_hide_mounts", check=False)
            adb.su("rm -rf " + base, check=False)
        except Exception:
            pass
        print(output)
        # SUS_MAP has no removal operation in this pinned protocol. A cold boot
        # clears its inode rules before the test inode can be reused elsewhere.
        mumu.stop(args.instance)
        adb = mumu.start(args.instance)
        adb.su("rm -rf " + base, check=False)


if __name__ == "__main__":
    main()
