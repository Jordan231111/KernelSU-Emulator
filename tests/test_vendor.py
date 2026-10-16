import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import Error
from src.ksu_emulator.profiles import repository_file
from src.ksu_emulator.vendor import clean_vendor_root, specification, verify_vendor_cleanup
from src.ksu_emulator.common import sha256


class VendorCleanupTests(unittest.TestCase):
    def test_kernel_su_addons_do_not_look_like_a_remaining_magisk_provider(self):
        _, spec = specification("mumu-pro-1.9.2-arm64")
        hashes = {item["path"]: item["after_sha256"] for item in spec["files"]}
        hashes.update({path: sha256(repository_file(source)) for path, source in spec["boot_files"].items()})
        mumu = Mock()
        mumu.settings.return_value = {"vmRootEnable": False}
        adb = mumu.connect.return_value
        processes = ["root 100 vectord", "root 101 zygiskd64", "root 102 zygisk-ptrace64"]
        def read(command, **kwargs):
            if command.startswith("sha256sum "):
                return "\n".join(f"{digest}  {path}" for path, digest in hashes.items())
            if command == "ps -A":
                return "\n".join(processes)
            if command.startswith("dumpsys package "):
                return "disabledComponents:\n        com.netease.nemu_vapi_android.receiver.LaunchReceiver\n"
            if command.startswith("dumpsys activity services "):
                return ("* ServiceRecord{abc com.netease.nemu_vapi_android.service.ApiService}\n"
                        "    app=ProcessRecord{123}\n")
            return ""
        adb.su.side_effect = read
        adb.shell.side_effect = lambda command: "1" if command == "getprop sys.ksu_mumu.platform_ready" else ""
        result = verify_vendor_cleanup(mumu, 0)
        self.assertTrue(result["verified"])
        self.assertEqual(result["old_root_processes"], [])
        self.assertEqual(len(result["injection_module_processes"]), 3)
        processes.append("root 103 magiskd")
        result = verify_vendor_cleanup(mumu, 0)
        self.assertFalse(result["verified"])
        self.assertEqual(result["old_root_processes"], ["magiskd"])

    def test_unreviewed_deletions_are_rejected_before_device_access(self):
        _, original = specification("mumu-pro-1.9.2-arm64")
        for field, value in (("remove_files", [{"path": "/bin/sh", "sha256": "a" * 64}]),
                             ("disabled_receiver", "another.package/.Receiver"),
                             ("optional_aliases", ["/bin/sh"])):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                spec = copy.deepcopy(original)
                spec[field] = value
                path = Path(tmp) / "spec.json"
                path.write_text(json.dumps(spec))
                def source(name):
                    return path if name.endswith("vendor-cleanup.json") else repository_file(name)
                mumu = Mock()
                with patch("src.ksu_emulator.vendor.repository_file", side_effect=source), self.assertRaises(Error):
                    clean_vendor_root(mumu, 0)
                self.assertFalse(mumu.mock_calls)

    def test_candidate_requires_explicit_testing_flag(self):
        profile, spec = specification("mumu-pro-1.9.2-arm64")
        spec["status"] = "candidate"
        mumu = Mock()
        with patch("src.ksu_emulator.vendor.specification", return_value=(profile, spec)), self.assertRaises(Error):
            clean_vendor_root(mumu, 0)
        self.assertFalse(mumu.mock_calls)
