import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import Error, load_profile, save_json, sha256
from src.ksu_emulator.install import install, verify
from src.ksu_emulator.maintenance import compare_capture, read_capture, require_lab, clone_lab
from src.ksu_emulator.profiles import build_settings, validate_profile
from src.ksu_emulator.upgrade import upgrade_clone
from src.ksu_emulator.upstream import select_manager


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile()

    def test_app_only_update_is_candidate_for_reuse(self):
        result = compare_capture({"evidence": {**self.profile, "emulator_version": "2.0"}}, self.profile)
        self.assertEqual(result["classification"], "app-update-same-kernel")
        self.assertTrue(result["reuse_build_candidate"])

    def test_same_release_string_is_not_abi_proof(self):
        for key in ("kernel_image_sha256", "config_gz_sha256", "vendor_module_sha256", "kernel_version"):
            with self.subTest(key=key):
                result = compare_capture({"evidence": {**self.profile, key: "changed"}}, self.profile)
                self.assertFalse(result["reuse_build_candidate"])
                self.assertEqual(result["classification"], "kernel-port-required")

    def test_missing_driver_evidence_refuses_reuse(self):
        result = compare_capture({"evidence": {**self.profile, "vendor_module_sha256": None}}, self.profile)
        self.assertEqual(result["classification"], "insufficient-evidence")
        self.assertFalse(result["reuse_build_candidate"])

    def test_recipe_injection_and_malformed_fields_are_rejected(self):
        for key, value in (("ksu_tag", 'v3; touch /tmp/unwanted'), ("ksud_sha256", None),
                           ("ksu_package", []), ("ksu_version", True)):
            with self.subTest(key=key), self.assertRaises(Error):
                validate_profile({**self.profile, key: value})
        for key, value in (("module_directory", "../other"), ("kernel_config", "/etc/passwd"),
                           ("local_version", "$(command)"), ("uapi_version", True)):
            with self.subTest(key=key), self.assertRaises(Error):
                validate_profile({**self.profile, "build": {**build_settings(self.profile), key: value}})

    def test_new_profile_requires_explicit_schema_and_recipe(self):
        with self.assertRaises(Error):
            validate_profile({**self.profile, "id": "new-profile"})
        with self.assertRaises(Error):
            validate_profile({**self.profile, "id": "new-profile", "schema": 2})

    def test_capture_detects_changed_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            for name in ("config.gz", "kernel.config"):
                (path / name).write_bytes(b"original")
            save_json(path / "report.json", {"schema": 1, "evidence": {},
                "files": {name: sha256(path / name) for name in ("config.gz", "kernel.config")}})
            read_capture(path)
            (path / "kernel.config").write_bytes(b"changed")
            with self.assertRaises(Error):
                read_capture(path)

    def test_candidate_install_is_blocked_before_instance_changes(self):
        manifest = {"profile": {**self.profile, "validation": {"status": "candidate"}}}
        mumu = Mock()
        with patch("src.ksu_emulator.install.validate_bundle", return_value=manifest), self.assertRaises(Error):
            install(mumu, 2, Path("unused"))
        self.assertFalse(mumu.mock_calls)

    def test_fork_switch_is_rejected_before_cloning(self):
        other = copy.deepcopy(self.profile)
        other["ksu_package"] = "another.manager"
        mumu = Mock()
        with patch("src.ksu_emulator.upgrade.validate_bundle", side_effect=[{"profile": self.profile}, {"profile": other}]), self.assertRaises(Error):
            upgrade_clone(mumu, 2, Path("old"), Path("new"), "Lab")
        self.assertFalse(mumu.mock_calls)

    def test_running_source_is_restarted_if_clone_fails(self):
        mumu = Mock()
        mumu.info.return_value = {"state": "running"}
        mumu.call.side_effect = Error("clone failed")
        with self.assertRaises(Error):
            clone_lab(mumu, 2, "Lab")
        mumu.stop.assert_called_once_with(2)
        mumu.start.assert_called_once_with(2)

    def test_instance_index_reuse_does_not_reuse_lab_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            save_json(root / "out/labs/2.json", {"index": 2, "bundle_path": str(root / "old")})
            mumu = Mock()
            mumu.info.return_value = {"bundle_path": str(root / "new")}
            with patch("src.ksu_emulator.maintenance.ROOT", root), self.assertRaises(Error):
                require_lab(mumu, 2)

    def test_ambiguous_manager_release_requires_explicit_choice(self):
        release = {"assets": [{"name": "one-release.apk"}, {"name": "two-release.apk"}]}
        with self.assertRaises(Error):
            select_manager(release)
        self.assertEqual(select_manager(release, "two-release.apk")["name"], "two-release.apk")

    def test_hidden_module_requires_real_api_evidence(self):
        mumu = Mock()
        adb = mumu.connect.return_value
        evidence = {**self.profile, "kernel_modules": "vaddress 100 0", "installer_ready": "1"}
        adb.shell.return_value = '{"version":33355,"uapi":5}'
        with patch("src.ksu_emulator.install.probe", return_value=evidence.copy()):
            result = verify(mumu, 2)
        self.assertFalse(result["kernel_module_listed"])
        self.assertTrue(result["persistent_install_ready"])
        adb.shell.return_value = '{"version":1,"uapi":5}'
        with patch("src.ksu_emulator.install.probe", return_value=evidence.copy()):
            self.assertFalse(verify(mumu, 2)["persistent_install_ready"])

    def test_fresh_install_does_not_require_pregranting_shell_root(self):
        mumu = Mock()
        mumu.connect.return_value.shell.side_effect = Error("No control fd for unapproved Shell")
        evidence = {**self.profile, "kernel_modules": "kernelsu 380928 1 - Live", "installer_ready": "1"}
        with patch("src.ksu_emulator.install.probe", return_value=evidence):
            self.assertTrue(verify(mumu, 2)["persistent_install_ready"])


if __name__ == "__main__":
    unittest.main()
