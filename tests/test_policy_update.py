import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import Error
from src.ksu_emulator.hardening import specification
from src.ksu_emulator.policy_update import migration_for, run_compiler, update_policy
from src.ksu_emulator.profiles import repository_file


class PolicyUpdateTests(unittest.TestCase):
    def test_only_reviewed_policy_recipes_are_accepted(self):
        _, spec = specification()
        entry = migration_for(spec["base_profile"],
            "9fee9b8d1f0a4fa41cb4a16fa8865b58acef054aafc3ef8d6e315750bf533136", spec)
        self.assertEqual(entry["policy_sha256"],
            "4633c3da7955b071e4d3a212934cdfcc39458b745d93d2cc7cef30296753023a")
        with self.assertRaises(Error):
            migration_for(spec["base_profile"], "f" * 64, spec)

    def test_catalog_cannot_replace_arbitrary_system_files(self):
        _, spec = specification()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            path.write_text(json.dumps({"schema": 1, "previous": [{
                "recipe_sha256": "a" * 64, "policy_sha256": "b" * 64,
                "rules_sha256": "c" * 64,
                "output_policy_sha256": spec["compiled_policy_sha256"],
                "boot_sha256": {"../../bin/sh": "d" * 64}}]}))
            with patch("src.ksu_emulator.policy_update.repository_file", return_value=path), self.assertRaises(Error):
                migration_for("profile", "a" * 64, spec)

    def test_damaged_installation_is_rejected_before_download_or_write(self):
        mumu = Mock()
        mumu.settings.return_value = {"systemFilePermissionType": 1, "vmRootEnable": False}
        adb = mumu.connect.return_value
        adb.su.return_value = json.dumps({"recipe_sha256":
            "9fee9b8d1f0a4fa41cb4a16fa8865b58acef054aafc3ef8d6e315750bf533136"})
        with patch("src.ksu_emulator.policy_update.verify_hardening", return_value={"verified": False}), \
             patch("src.ksu_emulator.policy_update.download") as download, self.assertRaises(Error):
            update_policy(mumu, 0)
        download.assert_not_called()
        adb.push.assert_not_called()
        adb.shell.assert_not_called()
        adb.su.assert_called_once_with("cat /system/etc/ksu-mumu-policy/state.json")

    def test_compiler_diagnostic_is_fatal_even_with_zero_exit_status(self):
        adb = Mock()
        adb.call.return_value = subprocess.CompletedProcess([], 0, b"type does not exist", b"")
        with self.assertRaises(Error):
            run_compiler(adb, "policy-tool")

    def test_fresh_install_and_migration_have_identical_additional_rules(self):
        _, spec = specification()
        full = repository_file(spec["policy_rules"]).read_text()
        delta = repository_file("profiles/mumu-pro-1.9.2-arm64/hardening/policy-v1.0.3.rules").read_text()
        self.assertTrue(full.endswith(delta))
        marker = repository_file(spec["boot_files"]["mark-boot.sh"]).read_text()
        self.assertIn("for service in " + " ".join(spec["required_services"]) + "; do", marker)


if __name__ == "__main__":
    unittest.main()
