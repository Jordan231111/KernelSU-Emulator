#!/usr/bin/env python3
"""Exercise canonical SUSFS commands with disposable fixtures on one instance."""
import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
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
    base = "/data/local/tmp/ksu-api-" + uuid.uuid4().hex[:12]
    cli = "/data/adb/modules/mumu_susfs/ksu_susfs"
    raw = "/data/adb/modules/mumu_susfs/susfs-sc"
    report = {"instance": args.instance, "boot_id": adb.su("cat /proc/sys/kernel/random/boot_id"),
              "build_hashes": adb.su("sha256sum /system/etc/ksu-emulator/kernelsu.ko /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko"),
              "cases": {}}
    output = ROOT / "out/audit/susfs-public-api.json"

    def case(name, expected, observed, passed):
        report["cases"][name] = {"expected": expected, "observed": observed, "passed": passed}
        save_json(output, report)
        if not passed:
            raise Error(name + " did not match its expected behavior")

    def tool(*arguments):
        return adb.su(" ".join(shlex.quote(x) for x in (cli, *arguments)))

    try:
        adb.shell("mkdir -m 0755 " + base)
        for name in ("state_probe", "path_probe", "path_probe32"):
            adb.push(ROOT / "out/guest-tests/native" / name, base + "/" + name)
        adb.su(f"chmod 755 {base}/*; chcon u:object_r:system_file:s0 {base} {base}/*; "
               f"mkdir {base}/create; chmod 777 {base}/create; chcon u:object_r:system_file:s0 {base}/create")
        version, variant, features = tool("show", "version"), tool("show", "variant"), tool("show", "enabled_features")
        case("canonical_client", "Current universal client detects v2.4.0 / NON-GKI", {"version": version, "variant": variant, "features": features},
             version == "v2.4.0" and variant == "NON-GKI" and "CONFIG_KSU_SUSFS_SUS_PATH" in features)
        for caller in ("root", "app"):
            if caller == "app":
                adb.su(f"chown 19999:19999 {base}/create; chcon u:object_r:app_data_file:s0 {base}/create")
            observed = adb.su(f"{base}/state_probe {caller} create {base}/create")
            case("create_" + caller, "100 successful mkdir/rmdir pairs and 100 ENOENT missing-parent results", observed, "failures=0" in observed)
        modules = adb.su("cat /proc/modules")
        symbols = adb.su("grep -c -E '\\[(kernelsu|susfs_guard_lkm)\\]$' /proc/kallsyms || true")
        case("module_symbols", "Both modules omitted, vendor vaddress retained", {"modules": modules, "matching_symbol_lines": symbols},
             "kernelsu " not in modules and "susfs_guard_lkm " not in modules and "vaddress " in modules and symbols == "0")
        control = adb.su(f"{base}/path_probe /proc/susfs_path app")
        case("control_access", "Non-root app receives ENOENT and no directory entry", control,
             "stat=-1 errno=2" in control and "open=-1 errno=2" in control and "dirent=0" in control)
        compat = adb.call("shell", "su -c " + shlex.quote(f"{base}/path_probe32 /proc/susfs_path app"), check=False)
        report["compat32"] = {"stdout": compat.stdout.decode(errors="replace"),
                              "stderr": compat.stderr.decode(errors="replace"), "exit_code": compat.returncode,
                              "executed": b"uid=19999" in compat.stdout}
        # A queued path becomes hidden when the file appears and the timer resolves it.
        tool("add_sus_path_loop", base + "/future")
        adb.su(f"echo future > {base}/future; chmod 644 {base}/future; chcon u:object_r:system_file:s0 {base}/future")
        deadline = time.monotonic() + 20
        while True:
            observed = adb.su(f"{base}/path_probe {base}/future app")
            if "stat=-1 errno=2" in observed or time.monotonic() >= deadline:
                break
            time.sleep(1)
        case("path_loop", "An initially absent registered file becomes hidden within 20 seconds", observed, "stat=-1 errno=2" in observed)
        adb.su(f"echo 'del {base}/future' > /proc/susfs_path")
        # Independently format two tiny filesystems: their first files both get
        # inode 12. These are disposable fixtures, not emulator disk copies.
        mkfs = shutil.which("mke2fs") or "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs"
        # ADB uploads run as Shell, which cannot create system_file objects.
        adb.su("chcon u:object_r:shell_data_file:s0 " + base)
        with tempfile.TemporaryDirectory(prefix="ksu-fs-test-") as tmp:
            for name in ("a", "b"):
                image = Path(tmp) / (name + ".img")
                with image.open("wb") as stream:
                    stream.truncate(8 << 20)
                subprocess.run([mkfs, "-q", "-F", "-t", "ext4", "-O",
                                "none,extent,filetype,sparse_super,large_file", str(image)], check=True)
                adb.push(image, base + "/" + image.name)
        adb.su("chcon u:object_r:system_file:s0 " + base)
        # Equal inode numbers on different filesystems must not share a rule.
        observed = adb.su(
            f"set -e; mkdir {base}/a {base}/b; mount -t ext4 -o loop {base}/a.img {base}/a; mount -t ext4 -o loop {base}/b.img {base}/b; "
            f"trap \"echo 'del {base}/a/same' > /proc/susfs_path; umount {base}/b; umount {base}/a\" EXIT; "
            f"echo a > {base}/a/same; echo b > {base}/b/same; chmod 755 {base}/a {base}/b; chmod 644 {base}/a/same {base}/b/same; "
            f"chcon u:object_r:system_file:s0 {base}/a {base}/b {base}/a/same {base}/b/same; "
            f"stat -c '%i %d' {base}/a/same {base}/b/same; {cli} add_sus_path {base}/a/same; "
            f"echo HIDDEN; {base}/path_probe {base}/a/same app; echo VISIBLE; {base}/path_probe {base}/b/same app")
        hidden, visible = observed.split("VISIBLE\n", 1)
        identities = re.findall(r"^(\d+) (\d+)$", observed, re.M)
        case("filesystem_identity", "A hidden ext4 inode does not hide the same inode number/name on another ext4", observed,
             len(identities) == 2 and identities[0][0] == identities[1][0] and identities[0][1] != identities[1][1]
             and "dirent=0" in hidden and "dirent=1" in visible and "stat=0 errno=0" in visible)
        # The public redirection command must preserve the open notification.
        adb.su(f"echo original > {base}/original; echo replacement > {base}/replacement; chmod 644 {base}/original {base}/replacement; "
               f"chcon u:object_r:system_file:s0 {base}/original {base}/replacement")
        tool("add_open_redirect", base + "/original", base + "/replacement", "2")
        observed = adb.su(f"{base}/state_probe app watch {base}/replacement {base}/original")
        case("redirect_inotify", "The redirected file emits IN_OPEN (0x20)", observed,
             bool(re.search(r"notify_bytes=[1-9][0-9]* mask=20", observed)))
        adb.su(f"echo 'del {base}/original' > /proc/susfs_open_redirect")
        # Retrying mount enable used to leave disabled kprobes behind.
        toggles = [tool("hide_sus_mnts_for_non_su_procs", value) for value in ("0", "1", "0", "1")]
        mount_status = adb.su("cat /sys/module/susfs_guard_lkm/parameters/mount_stat")
        case("mount_reenable", "Two off/on cycles finish with all three proc mount views armed", {"commands": toggles, "status": mount_status},
             "show_probes=3/3" in mount_status)
        tool("set_uname", "4.19.195-ksu-qa", "ksu-qa-version")
        observed = {caller: adb.su(f"{base}/state_probe {caller} uname") for caller in ("root", "app")}
        case("uname", "Both callers see the requested release/version", observed,
             all("release=4.19.195-ksu-qa" in text and "version=ksu-qa-version" in text for text in observed.values()))
        original_cmdline_hash = hashlib.sha256(adb.su("cat /proc/cmdline").encode()).hexdigest()
        adb.su(f"printf 'ksu.qa=controlled' > {base}/cmdline")
        tool("set_cmdline_or_bootconfig", base + "/cmdline")
        observed = adb.su("cat /proc/cmdline")
        case("cmdline", "The controlled command line replaces the proc view", {"before_sha256": original_cmdline_hash, "after": observed}, observed == "ksu.qa=controlled")
        states = []
        for value in ("1", "0", "1", "0"):
            tool("enable_log", value)
            states.append(adb.su("cat /proc/susfs_enable_log"))
        case("logging", "The log switch follows on/off/on/off", states, [x.strip() for x in states] == ["1", "0", "1", "0"])
        # These are documented gaps, not successful implementations.
        report["unsupported_commands"] = {}
        for name, command in (("canonical_try_umount", "0x55580"),):
            result = adb.su(f"{raw} {command} 7e000000", check=False)
            report["unsupported_commands"][name] = {"expected": "Unsupported sentinel 126 remains unchanged", "observed": result}
        report["passed"] = True
    except Exception as exc:
        report.update(passed=False, error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        save_json(output, report)
        try:
            adb.su(f"echo 'del {base}/future' > /proc/susfs_path; rm -rf {base}", check=False)
        except Error:
            pass
        mumu.stop(args.instance)
        adb = mumu.start(args.instance)
        adb.su("rm -rf " + base, check=False)
        print(output)


if __name__ == "__main__":
    main()
