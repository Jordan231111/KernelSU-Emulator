#!/usr/bin/env python3
"""Exercise the installed cleanup adapter with fixed requests and denied callers."""
import argparse
import json
import shlex
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT
from ksu_emulator.install import verify
from ksu_emulator.mumu import MuMu


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    args = parser.parse_args()
    mumu = MuMu()
    adb = mumu.connect(args.instance)
    assert "uid:19999" not in adb.shell("pm list packages -U")
    assert adb.su("cat /sys/fs/selinux/enforce") == "1"
    base = "/data/local/tmp/ksu-trim-qa-" + uuid.uuid4().hex[:12]
    disk = Path(mumu.info(args.instance)["bundle_path"]) / "data.qcow2"
    request = b"fstrim /data && sync && exit 0 \n  || exit 1\n"
    report = {"instance": args.instance, "expected": {
        "api": "system UID with no capabilities may submit the exact trim request",
        "ordinary_app": "legacy helper and maintenance socket both return ENOENT",
        "other_system": "legacy path remains absent outside the MuMu API process",
        "invalid_command": "rejected without shell execution",
        "disconnect": "service survives a caller closing its connection",
        "data": "retained file checksum unchanged; discarded allocation reclaimed",
    }, "cases": {}}

    def call(mode, payload=request):
        result = subprocess.run([adb.executable, "-s", adb.serial, "shell", "-T",
                                 "su -c " + shlex.quote(base + "/probe " + mode)],
                                input=payload, capture_output=True, timeout=110)
        value = {"exit": result.returncode, "stdout": result.stdout.decode(errors="replace"),
                 "stderr": result.stderr.decode(errors="replace")}
        report["cases"][mode] = value
        return value

    try:
        adb.shell(f"mkdir -m 0755 {base}")
        adb.push(ROOT / "out/guest-tests/native/maintenance_probe", base + "/probe")
        adb.su(f"chmod 755 {base}/probe; chcon u:object_r:system_file:s0 {base} {base}/probe; "
               f"dd if=/dev/urandom of={base}/retained bs=1048576 count=1 conv=fsync")
        before = adb.su(f"sha256sum {base}/retained").split()[0]
        adb.su(f"dd if=/dev/urandom of={base}/discarded bs=1048576 count=256 conv=fsync")
        allocated = disk.stat().st_blocks * 512
        adb.su(f"rm {base}/discarded; sync")
        r = call("api")
        assert r["exit"] == 0 and "trimmed" in r["stdout"] and "capabilities=0" in r["stdout"] and not r["stderr"], r
        report["allocation"] = {"before_trim": allocated, "after_trim": disk.stat().st_blocks * 512}
        assert allocated - report["allocation"]["after_trim"] > 200 * 1024 * 1024, report["allocation"]
        for mode in ("other-system", "app"):
            r = call(mode)
            # The probe returns 9 only for ENOENT. app_zygote cannot write the
            # inherited root FIFO; its exit status is the reporting channel.
            assert r["exit"] == 9, r
            if mode == "other-system":
                assert "exec_errno=2" in r["stdout"], r
        r = call("app-socket")
        assert r["exit"] == 0, r  # Native probe requires precisely ENOENT.
        r = call("invalid", b"id; touch " + (base + "/injected").encode() + b"\n")
        assert r["exit"] == 1 and "failed" in r["stderr"], r
        r = call("trailing", request + b"touch " + (base + "/injected").encode() + b"\n")
        assert r["exit"] == 0 and not adb.su(f"test -e {base}/injected && echo created", check=False), r
        r = call("disconnect")
        assert r["exit"] == 0 and "connect=0" in r["stdout"], r
        r = call("after-disconnect")
        assert r["exit"] == 0 and not r["stderr"], r
        report["retained_checksum_matches"] = before == adb.su(f"sha256sum {base}/retained").split()[0]
        assert report["retained_checksum_matches"]
        report["installation"] = verify(mumu, args.instance, root=True)
        assert report["installation"]["disk_cleanup_ready"]
        assert not adb.su("find /system/bin /system/xbin -maxdepth 1 \\( -name su -o -name mu_bak \\)")
        report["passed"] = True
    except Exception as error:
        report.update(passed=False, error=str(error))
        raise
    finally:
        output = ROOT / "out/audit/disk-cleanup-qualification.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        adb.su("rm -rf " + base, check=False)
        print(output)


if __name__ == "__main__":
    main()
