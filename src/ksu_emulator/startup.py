"""Migrate reviewed hardening startup files without replacing SELinux policy."""
from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

from .common import Error, sha256
from .hardening import recipe_hash, specification, verify_hardening, wait_hardening
from .mumu import MuMu
from .profiles import HEX256, matches, repository_file


def migration_for(profile_id: str, installed_recipe: str, spec: dict) -> dict:
    path = repository_file(f"profiles/{profile_id}/hardening/startup-migrations.json")
    catalog = json.loads(path.read_text())
    if catalog.get("schema") != 1 or not isinstance(catalog.get("previous"), list):
        raise Error("Invalid startup migration catalog")
    for entry in catalog["previous"]:
        if not isinstance(entry, dict) or not matches(HEX256, entry.get("recipe_sha256")):
            raise Error("Invalid previous startup recipe")
        hashes = entry.get("boot_sha256")
        if not isinstance(hashes, dict) or not hashes or not set(hashes) <= set(spec["boot_files"]):
            raise Error("Startup migrations can only replace known hardening boot files")
        if any(not matches(HEX256, value) for value in hashes.values()):
            raise Error("Startup migrations require exact input hashes")
        if entry["recipe_sha256"] == installed_recipe:
            return entry
    raise Error("Installed hardening recipe has no reviewed startup migration")


def migrate_hardening_startup(mumu: MuMu, index: int, profile_id: str) -> dict:
    """Called after the core updater has validated both bundles and installed APK."""
    _, spec = specification(profile_id)
    adb = mumu.connect(index)
    state = json.loads(adb.su("cat /system/etc/ksu-mumu-policy/state.json"))
    new_recipe = recipe_hash(spec)
    previous = state.get("recipe_sha256")
    if previous == new_recipe:
        if not wait_hardening(mumu, index, profile_id)["verified"]:
            raise Error("Resolve the existing SELinux configuration before updating")
        return {"changed": False}
    migration = migration_for(profile_id, previous, spec)
    checked = verify_hardening(mumu, index, profile_id, _expected_recipe=previous,
                               _boot_hashes=migration["boot_sha256"])
    if not checked["verified"]:
        raise Error("Previous hardening files, labels or running services failed verification")
    state["recipe_sha256"] = new_recipe
    stage = "/data/local/tmp/ksu-startup-" + uuid.uuid4().hex
    adb.shell("mkdir -m 0700 " + stage)
    try:
        with tempfile.TemporaryDirectory(prefix="ksu-startup-") as temp:
            state_file = Path(temp) / "state.json"
            state_file.write_text(json.dumps(state, indent=2) + "\n")
            files = [(name, repository_file(spec["boot_files"][name]),
                      "/system/etc/init/" + name if name.endswith(".rc") else "/system/etc/ksu-mumu-policy/" + name,
                      "0644" if name.endswith(".rc") else "0755")
                     for name in migration["boot_sha256"]]
            files.append(("state.json", state_file, "/system/etc/ksu-mumu-policy/state.json", "0644"))
            for name, local, _, _ in files:
                adb.push(local, stage + "/" + name)
                if adb.su("sha256sum " + stage + "/" + name).split()[0] != sha256(local):
                    raise Error("Staged startup file checksum mismatch")
            adb.su("mount -o remount,rw /system")
            for name, local, remote, mode in files:
                adb.su(f"set -e; cp {stage}/{name} {remote}.ksu-new; chmod {mode} {remote}.ksu-new; "
                       f"mv {remote}.ksu-new {remote}; restorecon {remote}")
                if adb.su("sha256sum " + remote).split()[0] != sha256(local):
                    raise Error("Installed startup file checksum mismatch")
            adb.su("sync")
        if not verify_hardening(mumu, index, profile_id)["verified"]:
            raise Error("Updated startup recipe failed verification")
        return {"changed": True, "from_recipe": previous, "to_recipe": new_recipe}
    finally:
        try:
            adb.su("rm -rf " + stage, check=False)
        except (Error, OSError):
            pass
