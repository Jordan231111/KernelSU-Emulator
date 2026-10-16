import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src.ksu_emulator.common import ROOT


@unittest.skipIf(os.name == "nt" or not shutil.which("sh"), "Requires a POSIX shell")
class StartupLogTests(unittest.TestCase):
    def test_trim_only_preserves_latest_bytes_and_other_files(self):
        with tempfile.TemporaryDirectory(prefix="ksu-log-test-") as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            script = root / "boot.sh"
            script.write_text((ROOT / "scripts/boot.sh.in").read_text().replace(
                "/data/adb/ksu-emulator", str(logs)))
            content = b"old data\n" * 10000 + b"latest message\n\n"
            (logs / "boot.log").write_bytes(content)
            small = logs / "policy.log"
            small.write_bytes(b"small\n")
            small_mtime = small.stat().st_mtime_ns
            outside = root / "outside.log"
            outside.write_bytes(b"leave this alone" * 10000)
            (logs / "susfs.log").symlink_to(outside)
            marker = logs / "enforcing-boot-ok"
            marker.write_text("boot identity")
            subprocess.run(["sh", str(script), "--trim-logs"], check=True)
            self.assertEqual((logs / "boot.log").read_bytes(), content[-65536:])
            self.assertEqual(small.read_bytes(), b"small\n")
            self.assertEqual(small.stat().st_mtime_ns, small_mtime)
            self.assertEqual(outside.read_bytes(), b"leave this alone" * 10000)
            self.assertEqual(marker.read_text(), "boot identity")
            self.assertEqual({p.name for p in logs.iterdir()}, {
                "boot.log", "policy.log", "susfs.log", "enforcing-boot-ok"})
            before = (logs / "boot.log").stat().st_mtime_ns
            subprocess.run(["sh", str(script), "--trim-logs"], check=True)
            self.assertEqual((logs / "boot.log").stat().st_mtime_ns, before)

    def test_trim_only_does_not_require_an_installed_guest(self):
        with tempfile.TemporaryDirectory(prefix="ksu-log-test-") as directory:
            script = Path(directory) / "boot.sh"
            missing = Path(directory) / "absent"
            script.write_text((ROOT / "scripts/boot.sh.in").read_text().replace(
                "/data/adb/ksu-emulator", str(missing)))
            subprocess.run(["sh", str(script), "--trim-logs"], check=True)
            self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
