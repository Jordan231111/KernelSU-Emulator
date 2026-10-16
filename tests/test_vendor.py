import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import Error
from src.ksu_emulator.profiles import repository_file
from src.ksu_emulator.vendor import clean_vendor_root, specification


class VendorCleanupTests(unittest.TestCase):
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
