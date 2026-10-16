import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.ksu_emulator.common import Error
from src.ksu_emulator.hardening import specification
from src.ksu_emulator.startup import migrate_hardening_startup, migration_for


class StartupMigrationTests(unittest.TestCase):
    def test_only_the_reviewed_previous_recipe_is_accepted(self):
        _, spec = specification()
        with self.assertRaises(Error):
            migration_for("mumu-pro-1.9.2-arm64", "0" * 64, spec)
        entry = migration_for("mumu-pro-1.9.2-arm64", "d48bcc1befdc26f48ddd9322e0d7157b205f7706ed039f6ba3d6e6e8f12715aa", spec)
        self.assertEqual(set(entry["boot_sha256"]), {"guard.sh"})

    def test_catalog_cannot_turn_boot_update_into_policy_replacement(self):
        _, spec = specification()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps({"schema": 1, "previous": [{"recipe_sha256": "a" * 64,
                "boot_sha256": {"../../vendor/etc/selinux/precompiled_sepolicy": "b" * 64}}]}))
            with patch("src.ksu_emulator.startup.repository_file", return_value=path), self.assertRaises(Error):
                migration_for("profile", "a" * 64, spec)

    def test_modified_previous_installation_is_not_written(self):
        mumu = Mock()
        adb = mumu.connect.return_value
        adb.su.return_value = json.dumps({"recipe_sha256": "d48bcc1befdc26f48ddd9322e0d7157b205f7706ed039f6ba3d6e6e8f12715aa"})
        with patch("src.ksu_emulator.startup.verify_hardening", return_value={"verified": False}), self.assertRaises(Error):
            migrate_hardening_startup(mumu, 0, "mumu-pro-1.9.2-arm64")
        adb.push.assert_not_called()
        adb.shell.assert_not_called()
        adb.su.assert_called_once_with("cat /system/etc/ksu-mumu-policy/state.json")
