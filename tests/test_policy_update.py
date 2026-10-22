import copy
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
        adb.su.side_effect = [json.dumps({"recipe_sha256":
            "9fee9b8d1f0a4fa41cb4a16fa8865b58acef054aafc3ef8d6e315750bf533136"}),
            "4633c3da7955b071e4d3a212934cdfcc39458b745d93d2cc7cef30296753023a  policy"]
        with patch("src.ksu_emulator.policy_update.verify_hardening", return_value={"verified": False}), \
             patch("src.ksu_emulator.policy_update.download") as download, self.assertRaises(Error):
            update_policy(mumu, 0)
        download.assert_not_called()
        adb.push.assert_not_called()
        adb.shell.assert_not_called()
        self.assertEqual(adb.su.call_count, 2)

    def test_navigation_migration_pins_both_previous_serializations_and_labels(self):
        _, spec = specification()
        entry = migration_for(spec["base_profile"],
            "cb720285ae996276fbd3c0d9e14276a541f88f4b0c072bc2eef86702dac8c70e", spec)
        self.assertEqual(entry["equivalent_policy_sha256"],
            ["be0cbe355c08e0de3a28104bc0004fe5276cd965ee8810b145a5819b23240115"])
        self.assertEqual(entry["previous_labels"], {
            "/system/bin/input": "u:object_r:system_file:s0",
            "/system/bin/cmd": "u:object_r:system_file:s0"})
        self.assertEqual(set(entry["file_repairs"]), {"/system/etc/selinux/plat_file_contexts"})

    def test_new_migration_fields_reject_unreviewed_paths_hashes_and_labels(self):
        _, spec = specification()
        original = json.loads(repository_file(
            f"profiles/{spec['base_profile']}/hardening/policy-migrations.json").read_text())
        bad_fields = [
            {"file_repairs": {"/system/bin/sh": {}}},
            {"file_repairs": {"/system/etc/selinux/plat_file_contexts": {
                "before_sha256": "a" * 64, "patch_sha256": "b" * 64,
                "patch": "profiles/mumu-pro-1.9.2-arm64/hardening/navigation-labels.patch"}}},
            {"previous_labels": {"/data/local/tmp/unreviewed": "u:object_r:shell_exec:s0"}},
            {"previous_labels": {"/system/bin/input": "u:object_r:shell_exec:s0; id"}},
            {"equivalent_policy_sha256": ["not-a-checksum"]},
        ]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            for fields in bad_fields:
                with self.subTest(fields=fields):
                    catalog = copy.deepcopy(original)
                    catalog["previous"][-1].update(fields)
                    path.write_text(json.dumps(catalog))
                    def resolve(name):
                        return path if name.endswith("policy-migrations.json") else repository_file(name)
                    with patch("src.ksu_emulator.policy_update.repository_file", side_effect=resolve), \
                         self.assertRaises(Error):
                        migration_for(spec["base_profile"], catalog["previous"][-1]["recipe_sha256"], spec)

    def test_unknown_previous_policy_is_rejected_before_write(self):
        mumu = Mock()
        mumu.settings.return_value = {"systemFilePermissionType": 1, "vmRootEnable": False}
        adb = mumu.connect.return_value
        adb.su.side_effect = [json.dumps({"recipe_sha256":
            "cb720285ae996276fbd3c0d9e14276a541f88f4b0c072bc2eef86702dac8c70e"}), "f" * 64 + "  policy"]
        with patch("src.ksu_emulator.policy_update.download") as download, self.assertRaises(Error):
            update_policy(mumu, 0)
        download.assert_not_called()
        adb.push.assert_not_called()
        adb.shell.assert_not_called()

    def test_compiler_diagnostic_is_fatal_even_with_zero_exit_status(self):
        adb = Mock()
        adb.call.return_value = subprocess.CompletedProcess([], 0, b"type does not exist", b"")
        with self.assertRaises(Error):
            run_compiler(adb, "policy-tool")

    def test_fresh_install_and_migration_have_identical_additional_rules(self):
        _, spec = specification()
        full = repository_file(spec["policy_rules"]).read_text()
        delta = repository_file("profiles/mumu-pro-1.9.2-arm64/hardening/policy-v1.0.1-to-current.rules").read_text()
        self.assertTrue(full.endswith(delta))
        navigation = repository_file("profiles/mumu-pro-1.9.2-arm64/hardening/policy-v1.0.5.rules").read_text()
        self.assertTrue(delta.endswith(navigation))
        marker = repository_file(spec["boot_files"]["mark-boot.sh"]).read_text()
        self.assertIn("for service in " + " ".join(spec["required_services"]) + "; do", marker)


if __name__ == "__main__":
    unittest.main()
