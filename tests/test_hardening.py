import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ksu_emulator.common import load_profile
from src.ksu_emulator.hardening import recipe_hash, specification
from src.ksu_emulator.maintenance import copy_extensions


class HardeningContractTests(unittest.TestCase):
    def test_promotion_does_not_change_installed_recipe_identity(self):
        _, spec = specification()
        candidate = copy.deepcopy(spec)
        candidate["status"] = "candidate"
        verified = copy.deepcopy(spec)
        verified["status"] = "verified"
        self.assertEqual(recipe_hash(candidate), recipe_hash(verified))
        verified.update(id="new-enforcing", base_profile="new-core")
        self.assertEqual(recipe_hash(candidate), recipe_hash(verified))
        verified["compiled_policy_sha256"] = "0" * 64
        self.assertNotEqual(recipe_hash(candidate), recipe_hash(verified))

    def test_optional_recipes_are_copied_as_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "profiles/old"
            target = root / "profiles/new"
            (source / "hardening").mkdir(parents=True)
            target.mkdir()
            (source / "hardening/rules").write_text("rules")
            (source / "kernel-symbols.txt").write_text("symbol")
            (source / "hardening.json").write_text(json.dumps({
                "id": "old-enforcing", "base_profile": "old", "status": "verified",
                "policy_rules": "profiles/old/hardening/rules", "compiled_policy_sha256": "a" * 64}))
            with patch("src.ksu_emulator.maintenance.ROOT", root):
                copy_extensions("old", "new")
            copied = json.loads((target / "hardening.json").read_text())
            self.assertEqual(copied["status"], "candidate")
            self.assertEqual(copied["base_profile"], "new")
            self.assertEqual(copied["policy_rules"], "profiles/new/hardening/rules")
            self.assertEqual((target / "hardening/rules").read_text(), "rules")
            self.assertEqual(copied["compiled_policy_sha256"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
