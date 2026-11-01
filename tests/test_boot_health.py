import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import ROOT
from src.ksu_emulator.hardening import wait_hardening


class BootHealthTests(unittest.TestCase):
    def test_boot_completed_does_not_bypass_service_stability(self):
        booting = {"verified": False, "fallback": None}
        healthy = {"verified": True, "fallback": None}
        with patch("src.ksu_emulator.hardening.verify_hardening", side_effect=[booting, booting, healthy]) as check, \
             patch("src.ksu_emulator.hardening.time.sleep"):
            self.assertEqual(wait_hardening(Mock(), 0, "profile"), healthy)
            self.assertEqual(check.call_count, 3)

    def test_permissive_fallback_is_returned_as_failure(self):
        failed = {"verified": False, "fallback": "timeout"}
        with patch("src.ksu_emulator.hardening.verify_hardening", return_value=failed) as check:
            self.assertEqual(wait_hardening(Mock(), 0, "profile"), failed)
            check.assert_called_once()

    def test_health_failure_is_returned_without_waiting_for_host_timeout(self):
        failed = {"verified": False, "fallback": None, "boot_health": "failed"}
        with patch("src.ksu_emulator.hardening.verify_hardening", return_value=failed) as check:
            self.assertEqual(wait_hardening(Mock(), 0, "profile"), failed)
            check.assert_called_once()


@unittest.skipIf(os.name == "nt" or not shutil.which("sh"), "Requires a POSIX shell")
class EnforcementScriptTests(unittest.TestCase):
    """Execute the production scripts with isolated files and simulated Android commands."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ksu-enforcement-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.base = self.root / "state"
        self.props = self.root / "properties"
        self.bin = self.root / "bin"
        for path in (self.base, self.props, self.bin):
            path.mkdir()
        (self.root / "boot-id").write_text("current-boot")
        self.mode = self.root / "enforce"
        self.mode.write_text("0")
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.defpath,
                    "TEST_ROOT": str(self.root), "TEST_BASE": str(self.base), "TEST_BIN": str(self.bin),
                    "TEST_PROPS": str(self.props), "TEST_UNHEALTHY": "", "TEST_RECOVER_AFTER": "999",
                    "TEST_READBACK": "1"}
        stubs = {
            "ksud": "exit 0\n",
            "sync": "exit 0\n",
            "cat": '''if [ "$1" = "$TEST_ROOT/enforce" ] && [ "$TEST_READBACK" = 0 ]; then
    printf 0
else
    exec /bin/cat "$@"
fi
''',
            "setprop": 'printf "%s" "${2-}" >"$TEST_PROPS/$1"\n',
            "getprop": '''polls=0
[ ! -f "$TEST_ROOT/polls" ] || read -r polls <"$TEST_ROOT/polls" || :
if [ "$1" = "init.svc.$TEST_UNHEALTHY" ] && [ "$polls" -lt "$TEST_RECOVER_AFTER" ]; then
    printf stopped
else
    printf running
fi
''',
            "sleep": '''polls=0
[ ! -f "$TEST_ROOT/polls" ] || read -r polls <"$TEST_ROOT/polls" || :
printf '%s' "$((polls+1))" >"$TEST_ROOT/polls"
''',
        }
        for name, text in stubs.items():
            path = self.bin / name
            path.write_text("#!/bin/sh\nset -eu\n" + text)
            path.chmod(0o755)

    def run_script(self, name):
        script = self.root / name
        text = (ROOT / "profiles/mumu-pro-1.9.2-arm64/hardening" / name).read_text()
        for original, replacement in (
                ("/data/adb/ksu-emulator", "$TEST_BASE"),
                ("/data/adb/ksud", '"$TEST_BIN/ksud"'),
                ("/proc/sys/kernel/random/boot_id", '"$TEST_ROOT/boot-id"'),
                ("/sys/fs/selinux/enforce", '"$TEST_ROOT/enforce"')):
            text = text.replace(original, replacement)
        script.write_text(text)
        return subprocess.run(["sh", str(script)], env=self.env, capture_output=True, text=True, timeout=30)

    def prop(self, name):
        return (self.props / ("sys.ksu_mumu_policy." + name)).read_text()

    def enable(self):
        result = self.run_script("guard.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mode.read_text(), "1")
        self.assertEqual(self.prop("enforcing_ready"), "1")

    def test_missing_checkpoint_neither_delays_nor_relaxes_enforcement(self):
        self.enable()
        self.assertEqual(self.prop("boot_health"), "pending")
        self.assertFalse((self.root / "polls").exists())
        self.assertFalse((self.base / "enforcing-pending").exists())

    def test_stale_pending_and_completed_boot_cannot_block_enforcement(self):
        (self.base / "enforcing-pending").write_text("old-boot")
        (self.base / "enforcing-boot-ok").write_text("old-boot")
        (self.props / "sys.ksu_mumu_policy.fallback").write_text("previous-boot")
        self.enable()
        self.assertFalse((self.base / "enforcing-pending").exists())
        self.assertEqual(self.prop("fallback"), "")

    def test_interrupted_boot_does_not_disable_next_boot(self):
        self.enable()  # No health checkpoint before the simulated next boot.
        (self.root / "boot-id").write_text("next-boot")
        self.mode.write_text("0")
        self.enable()
        result = self.run_script("mark-boot.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.base / "enforcing-boot-ok").read_text(), "next-boot")

    def test_health_success_publishes_current_boot_atomically(self):
        self.enable()
        (self.base / "enforcing-boot-ok").write_text("old-boot")
        result = self.run_script("mark-boot.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.prop("boot_health"), "passed")
        self.assertEqual((self.base / "enforcing-boot-ok").read_text(), "current-boot")
        self.assertFalse((self.base / "enforcing-boot-ok.new").exists())

    def test_service_timeout_reports_failure_and_leaves_enforcement_enabled(self):
        self.enable()
        self.env["TEST_UNHEALTHY"] = "media.swcodec"
        result = self.run_script("mark-boot.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.prop("boot_health"), "failed")
        self.assertEqual(self.mode.read_text(), "1")
        self.assertEqual(self.prop("enforcing_ready"), "1")
        self.assertFalse((self.base / "enforcing-boot-ok").exists())
        log = (self.base / "policy.log").read_text()
        self.assertIn("media.swcodec=stopped", log)
        self.assertIn("boot=current-boot", log)

    def test_service_recovery_can_succeed_on_last_health_check(self):
        self.enable()
        self.env.update(TEST_UNHEALTHY="media.swcodec", TEST_RECOVER_AFTER="50")
        result = self.run_script("mark-boot.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.prop("boot_health"), "passed")
        self.assertEqual(self.mode.read_text(), "1")
        self.assertEqual((self.root / "polls").read_text(), "59")

    def test_failed_enforcement_readback_cannot_report_ready(self):
        self.env["TEST_READBACK"] = "0"
        result = self.run_script("guard.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.prop("enforcing_ready"), "0")
        self.assertEqual(self.prop("boot_health"), "failed")

    def test_logging_failure_does_not_prevent_enforcement(self):
        (self.base / "policy.log").mkdir()  # Opening the diagnostic log must fail.
        result = self.run_script("guard.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mode.read_text(), "1")
        self.assertEqual(self.prop("enforcing_ready"), "0")
        self.assertEqual(self.prop("boot_health"), "failed")

    def test_health_logging_failure_reports_unhealthy_without_relaxing_mode(self):
        self.enable()
        (self.base / "policy.log").unlink()
        (self.base / "policy.log").mkdir()
        result = self.run_script("mark-boot.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.mode.read_text(), "1")
        self.assertEqual(self.prop("boot_health"), "failed")

    def test_health_check_rejects_actual_permissive_mode(self):
        self.enable()
        self.mode.write_text("0")  # Simulate an independent privileged writer.
        result = self.run_script("mark-boot.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.prop("boot_health"), "failed")
        self.assertFalse((self.base / "enforcing-boot-ok").exists())
