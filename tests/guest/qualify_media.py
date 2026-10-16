"""Generate an original clip, exercise MuMu's video service, remove all payloads."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ksu_emulator.common import Error, run
from ksu_emulator.mumu import MuMu


def qualify(instance: int, codec: str = "c2.android.avc.decoder", encoder: str = "libx264",
            size: str = "1168x544", repeats: int = 1) -> dict:
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT", str(Path.home() / "Library/Android/sdk")))
    api = sdk / "platforms" / os.environ.get("ANDROID_PLATFORM", "android-35") / "android.jar"
    d8 = sdk / "build-tools" / os.environ.get("ANDROID_BUILD_TOOLS", "35.0.0") / "d8"
    adb = MuMu().connect(instance)
    boot = adb.shell("cat /proc/sys/kernel/random/boot_id")
    stage = "/data/local/tmp/ksu-codec-" + uuid.uuid4().hex
    records = []
    with tempfile.TemporaryDirectory(prefix="ksu-codec-") as temp:
        work = Path(temp)
        classes, dex = work / "classes", work / "dex"
        classes.mkdir(); dex.mkdir()
        run(["javac", "-source", "8", "-target", "8", "-bootclasspath", api,
             "-d", classes, ROOT / "tests/guest/CodecProbe.java"])
        run([d8, "--lib", api, "--min-api", "26", "--output", dex, *classes.glob("*.class")])
        jar = work / "probe.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.write(dex / "classes.dex", "classes.dex")
        clip = work / "clip.mp4"
        run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", f"testsrc2=size={size}:rate=30",
             "-t", "2", "-c:v", encoder, "-pix_fmt", "yuv420p", "-an", "-y", clip], timeout=60)
        adb.shell("mkdir -m 0700 " + stage)
        try:
            adb.push(jar, stage + "/probe.jar")
            adb.push(clip, stage + "/clip.mp4")
            adb.shell("chmod 0444 " + stage + "/probe.jar")
            for _ in range(repeats):
                result = adb.shell("CLASSPATH=" + stage + "/probe.jar app_process /system/bin CodecProbe " +
                                   stage + "/clip.mp4 " + shlex.quote(codec) + " 60", timeout=40, check=False)
                reports = [line[12:] for line in result.splitlines() if line.startswith("CODEC_PROBE=")]
                if len(reports) != 1:
                    raise Error("Codec probe did not return one report: " + result[-1600:])
                records.append(json.loads(reports[0]))
        finally:
            adb.shell("rm -rf " + stage, check=False)
    same_boot = adb.shell("cat /proc/sys/kernel/random/boot_id") == boot
    enforcing = adb.su("cat /sys/fs/selinux/enforce") == "1"
    return {"instance": instance, "boot_id": boot, "same_boot": same_boot, "enforcing": enforcing,
            "passed": same_boot and enforcing and all(item["passed"] for item in records), "runs": records}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", type=int, required=True)
    parser.add_argument("--codec", default="c2.android.avc.decoder")
    parser.add_argument("--encoder", default="libx264")
    parser.add_argument("--size", default="1168x544")
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    report = qualify(args.instance, args.codec, args.encoder, args.size, args.repeats)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
