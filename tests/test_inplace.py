import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import Error, load_profile
from src.ksu_emulator.hardening import wait_hardening
from src.ksu_emulator.upgrade import upgrade


class InPlaceMaintenanceTests(unittest.TestCase):
    def test_private_disk_is_required_before_any_update_write(self):
        manifest = {"profile": load_profile()}
        for mode, vendor_root in ((0, False), (1, True)):
            with self.subTest(mode=mode, vendor_root=vendor_root):
                mumu = Mock()
                mumu.settings.return_value = {"systemFilePermissionType": mode, "vmRootEnable": vendor_root}
                with patch("src.ksu_emulator.upgrade.validate_bundle", return_value=manifest), self.assertRaises(Error):
                    upgrade(mumu, 0, Path("old"), Path("new"))
                mumu.start.assert_not_called()
                mumu.stop.assert_not_called()
                mumu.configure.assert_not_called()
                mumu.connect.assert_not_called()

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
