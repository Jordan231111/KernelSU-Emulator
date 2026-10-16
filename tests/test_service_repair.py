import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ksu_emulator.common import Error
from src.ksu_emulator.service_repair import repair_binary


class ServiceRepairTests(unittest.TestCase):
    def repair(self, before, edits, expected=b"abXYef", input_hash=None):
        item = {"path": "/system/bin/example", "patch": "patch.json",
                "before_sha256": input_hash or hashlib.sha256(b"abcdef").hexdigest(),
                "after_sha256": hashlib.sha256(expected).hexdigest()}
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "patch.json"
            file.write_text(json.dumps({"schema": 1, **item, "edits": edits}))
            with patch("src.ksu_emulator.service_repair.repository_file", return_value=file):
                return repair_binary(before, item)

    def test_exact_bytes_and_hashes_are_required(self):
        edits = [{"offset": 2, "before": b"cd".hex(), "after": b"XY".hex()}]
        self.assertEqual(self.repair(b"abcdef", edits), b"abXYef")
        with self.assertRaises(Error):
            self.repair(b"abzdef", edits)

    def test_wrong_hunk_is_rejected_even_when_input_hash_matches(self):
        with self.assertRaises(Error):
            self.repair(b"abcdef", [{"offset": 2, "before": "0000", "after": "0101"}])

    def test_overlapping_and_out_of_bounds_edits_are_rejected(self):
        for edits in ([{"offset": 8, "before": "63", "after": "58"}],
                      [{"offset": 2, "before": "6364", "after": "5859"},
                       {"offset": 3, "before": "64", "after": "59"}]):
            with self.assertRaises(Error):
                self.repair(b"abcdef", edits)

    def test_output_hash_mismatch_is_rejected(self):
        with self.assertRaises(Error):
            self.repair(b"abcdef", [{"offset": 2, "before": "6364", "after": "5859"}], expected=b"wrong")
