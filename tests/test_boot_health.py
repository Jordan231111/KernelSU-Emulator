import unittest
from unittest.mock import Mock, patch

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
