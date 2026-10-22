"""Fingerprint-gated policy maintenance; no saved original or recovery copy."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

from .build import download
from .common import Error, PROFILE_ID, sha256
from .hardening import apply_text_patch, recipe_hash, specification, verify_hardening, wait_hardening
from .mumu import MuMu
from .profiles import HEX256, matches, repository_file
from .service_repair import repair_binary


def migration_for(profile_id: str, installed_recipe: str, spec: dict) -> dict:
    catalog = json.loads(repository_file(f"profiles/{profile_id}/hardening/policy-migrations.json").read_text())
    if catalog.get("schema") != 1 or not isinstance(catalog.get("previous"), list):
        raise Error("Invalid policy migration catalog")
    seen = set()
    found = None
    for entry in catalog["previous"]:
        if not isinstance(entry, dict):
            raise Error("Invalid policy migration entry")
        for key in ("recipe_sha256", "policy_sha256", "rules_sha256"):
            if not matches(HEX256, entry.get(key)):
                raise Error("Policy migrations require exact recipe, policy and rule hashes")
        equivalent = entry.get("equivalent_policy_sha256", [])
        if not isinstance(equivalent, list) or any(not matches(HEX256, value) for value in equivalent):
            raise Error("Previous policy serializations require reviewed hashes")
        if entry["recipe_sha256"] in seen:
            raise Error("Duplicate policy migration recipe")
        seen.add(entry["recipe_sha256"])
        hashes = entry.get("boot_sha256", {})
        if not isinstance(hashes, dict) or not set(hashes) <= set(spec["boot_files"]) or any(
                not matches(HEX256, value) for value in hashes.values()):
            raise Error("Policy migrations can only replace known boot files")
        binaries = entry.get("binary_sha256", {})
        if (not isinstance(binaries, dict) or not set(binaries) <= {i["path"] for i in spec.get("binary_repairs", [])}
                or any(not matches(HEX256, value) for value in binaries.values())):
            raise Error("Migration can only replace fingerprinted vendor helpers")
        repairs = entry.get("file_repairs", {})
        if not isinstance(repairs, dict) or not set(repairs) <= {i["path"] for i in spec["files"]}:
            raise Error("Migration can only patch known system files")
        for repair in repairs.values():
            if not isinstance(repair, dict) or any(not matches(HEX256, repair.get(key))
                                                  for key in ("before_sha256", "patch_sha256")):
                raise Error("System file migrations require exact input and patch hashes")
            if sha256(repository_file(repair.get("patch"))) != repair["patch_sha256"]:
                raise Error("System file migration patch differs from its reviewed hash")
        labels = entry.get("previous_labels", {})
        if (not isinstance(labels, dict) or not set(labels) <= set(spec["explicit_system_labels"])
                or any(not matches(r"u:object_r:[A-Za-z0-9_]+:s0", value) for value in labels.values())):
            raise Error("Migration can only relabel known system paths")
        rules = repository_file(entry.get("rules"))
        if sha256(rules) != entry["rules_sha256"]:
            raise Error("Policy migration rules differ from their reviewed hash")
        if entry["recipe_sha256"] == installed_recipe:
            found = entry
    if found is None:
        raise Error("Installed hardening recipe has no reviewed policy migration")
    return found


def run_compiler(adb, command: str) -> None:
    result = adb.call("shell", "su -c " + shlex.quote(command), check=False)
    output = (result.stdout + result.stderr).decode(errors="replace")
    if result.returncode or re.search(r"error|failed|syntax|does not exist|aborting", output, re.I):
        raise Error("Policy compiler rejected the repair: " + output[-2000:])


def update_policy(mumu: MuMu, index: int, profile_id: str = PROFILE_ID, *, experimental: bool = False) -> dict:
    """Apply a reviewed migration live and on disk; cold-boot validation follows separately."""
    profile, spec = specification(profile_id)
    if spec["status"] != "verified" and not experimental:
        raise Error("Policy maintenance requires a qualified policy specification")
    mumu.validate_app(profile)
    settings = mumu.settings(index)
    if settings.get("systemFilePermissionType") != 1 or settings.get("vmRootEnable"):
        raise Error("Policy maintenance requires the private Writable disk and vendor root disabled")
    adb = mumu.connect(index)
    state = json.loads(adb.su("cat /system/etc/ksu-mumu-policy/state.json"))
    previous, current = state.get("recipe_sha256"), recipe_hash(spec)
    if previous == current:
        checked = wait_hardening(mumu, index, profile_id)
        if not checked["verified"]:
            raise Error("Current policy files, labels or services failed verification")
        return {"changed": False, "verification": checked}
    migration = migration_for(profile_id, previous, spec)
    policy_sum = adb.su("sha256sum " + spec["policy_path"]).split()
    policy_hash = policy_sum[0] if policy_sum else ""
    if policy_hash not in {migration["policy_sha256"], *migration.get("equivalent_policy_sha256", [])}:
        raise Error("Previous policy checksum has no reviewed migration")
    checked = verify_hardening(mumu, index, profile_id, _expected_recipe=previous,
                               _boot_hashes=migration.get("boot_sha256", {}),
                               _policy_hash=policy_hash,
                               _binary_hashes=migration.get("binary_sha256", {}),
                               _file_hashes={path: repair["before_sha256"]
                                             for path, repair in migration.get("file_repairs", {}).items()},
                               _labels=migration.get("previous_labels", {}))
    if not checked["verified"]:
        raise Error("Previous policy installation failed verification; nothing was written")
    boot = checked["boot_id"]
    stage = "/data/local/tmp/ksu-policy-" + uuid.uuid4().hex
    writable = False
    pending = []
    try:
        with tempfile.TemporaryDirectory(prefix="ksu-policy-") as temp:
            work = Path(temp)
            tool = spec["policy_tool"]
            apk = download(tool["apk"], work / "download")
            with zipfile.ZipFile(apk) as archive:
                binary = archive.read(tool["member"])
            if hashlib.sha256(binary).hexdigest() != tool["sha256"]:
                raise Error("Policy compiler binary checksum mismatch")
            (work / "policy-tool").write_bytes(binary)
            policy_path = spec["policy_path"]
            policy = adb.bytes("su -c " + shlex.quote("cat " + policy_path))
            if hashlib.sha256(policy).hexdigest() != policy_hash:
                raise Error("Policy changed after preflight")
            # Compiler input only; deleted together with all staging files.
            (work / "input-policy").write_bytes(policy)
            adb.shell("mkdir -m 0700 " + stage)
            inputs = [(work / "policy-tool", "policy-tool"), (work / "input-policy", "input-policy"),
                      (repository_file(migration["rules"]), "repair.rules")]
            for local, name in inputs:
                adb.push(local, stage + "/" + name)
                if adb.su("sha256sum " + stage + "/" + name).split()[0] != sha256(local):
                    raise Error("Staged policy input checksum mismatch")
            adb.su("chmod 0755 " + stage + "/policy-tool")
            run_compiler(adb, f"{stage}/policy-tool --load {stage}/input-policy "
                         f"--apply {stage}/repair.rules --save {stage}/compiled-policy")
            compiled_hash = adb.su("sha256sum " + stage + "/compiled-policy").split()[0]
            if compiled_hash not in {spec["compiled_policy_sha256"], *spec.get("equivalent_policy_sha256", [])}:
                raise Error("Compiled policy differs from the independently inspected outputs: " + compiled_hash)
            files = [("compiled-policy", policy_path, "0644", compiled_hash)]
            for i, item in enumerate(spec["files"]):
                repair = migration.get("file_repairs", {}).get(item["path"])
                if repair is None:
                    continue
                before = adb.bytes("su -c " + shlex.quote("cat " + item["path"]))
                data = apply_text_patch(before, {**item, "before_sha256": repair["before_sha256"],
                                                "patch": repair["patch"]}, work)
                local = work / ("system-file-" + str(i))
                local.write_bytes(data)
                adb.push(local, stage + "/" + local.name)
                if adb.su("sha256sum " + stage + "/" + local.name).split()[0] != item["after_sha256"]:
                    raise Error("Staged system file checksum mismatch")
                files.append((local.name, item["path"], "0644", item["after_sha256"]))
            restart_services = []
            for i, item in enumerate(spec.get("binary_repairs", [])):
                if item["path"] not in migration.get("binary_sha256", {}):
                    continue
                before = adb.bytes("su -c " + shlex.quote("cat " + item["path"]))
                restart_services.append(item["service"])
                if hashlib.sha256(before).hexdigest() == item["after_sha256"]:
                    continue
                data = repair_binary(before, item)
                local = work / ("helper-" + str(i))
                local.write_bytes(data)
                adb.push(local, stage + "/" + local.name)
                if adb.su("sha256sum " + stage + "/" + local.name).split()[0] != item["after_sha256"]:
                    raise Error("Staged vendor helper checksum mismatch")
                files.append((local.name, item["path"], "0755", item["after_sha256"]))
            for name in migration.get("boot_sha256", {}):
                local = repository_file(spec["boot_files"][name])
                remote = "/system/etc/init/" + name if name.endswith(".rc") else "/system/etc/ksu-mumu-policy/" + name
                adb.push(local, stage + "/" + name)
                if adb.su("sha256sum " + stage + "/" + name).split()[0] != sha256(local):
                    raise Error("Staged boot file checksum mismatch")
                files.append((name, remote, "0644" if name.endswith(".rc") else "0755", sha256(local)))
            state["recipe_sha256"] = current
            state.setdefault("installed", {})[policy_path] = compiled_hash
            state["installed"].update({item["path"]: item["after_sha256"] for item in spec["files"]
                                       if item["path"] in migration.get("file_repairs", {})})
            state["installed"].update({item["path"]: item["after_sha256"] for item in spec.get("binary_repairs", [])})
            local = work / "state.json"
            local.write_text(json.dumps(state, indent=2) + "\n")
            adb.push(local, stage + "/state.json")
            files.append(("state.json", "/system/etc/ksu-mumu-policy/state.json", "0644", sha256(local)))
            if mumu.connect(index).serial != adb.serial or adb.su("cat /proc/sys/kernel/random/boot_id") != boot:
                raise Error("The instance changed before policy publication")
            run_compiler(adb, f"{stage}/policy-tool --live --apply {stage}/repair.rules")
            if adb.su("cat /sys/fs/selinux/enforce") != "1":
                raise Error("Real SELinux enforcement changed during policy application")
            adb.su("mount -o remount,rw /system")
            writable = True
            for name, remote, mode, digest in files:
                path = remote + ".ksu-new"
                pending.append(path)
                adb.su(f"set -e; cp {stage}/{name} {path}; chown 0:0 {path}; chmod {mode} {path}")
                if adb.su("sha256sum " + path).split()[0] != digest:
                    raise Error("Policy publication checksum mismatch")
                adb.su(f"set -e; mv {path} {remote}; restorecon {remote}")
                if remote in spec["explicit_system_labels"]:
                    adb.su("chcon " + shlex.quote(spec["explicit_system_labels"][remote]) + " " + remote)
            for path in migration.get("previous_labels", {}):
                adb.su("chcon " + shlex.quote(spec["explicit_system_labels"][path]) + " " + shlex.quote(path))
            adb.su("sync")
            # A replaced executable can remain an open, unlinked inode until
            # its service exits. Restart the repaired service before remounting
            # ext4 read-only, and verify stable replacement rather than PID alone.
            for service in restart_services:
                old_pid = adb.su("getprop init.svc_debug_pid." + service)
                adb.su("setprop ctl.restart " + service)
                stable_pid, stable = "", 0
                for _ in range(40):
                    pid = adb.su("getprop init.svc_debug_pid." + service)
                    running = adb.su("getprop init.svc." + service) == "running"
                    if pid and pid != old_pid and running:
                        stable = stable + 1 if pid == stable_pid else 1
                        stable_pid = pid
                        if stable >= 5:
                            break
                    else:
                        stable = 0
                    time.sleep(0.2)
                if stable < 5:
                    raise Error("Repaired service did not restart stably: " + service)
        result = verify_hardening(mumu, index, profile_id)
        if not result["verified"]:
            raise Error("Published policy failed verification")
        return {"changed": True, "from_recipe": previous, "to_recipe": current,
                "policy_sha256": compiled_hash, "verification": result,
                "cold_boot_test_required": True}
    finally:
        try:
            adb.su("rm -rf " + stage, check=False)
            if writable:
                for path in pending:
                    adb.su("rm -f " + path, check=False)
                adb.su("sync; mount -o remount,ro /system")
        except (Error, OSError) as exc:
            if writable:
                raise Error("Could not finish policy cleanup/remount: " + str(exc)) from exc
