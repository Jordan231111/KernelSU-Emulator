"""Version-locked SELinux repairs applied to an explicitly selected instance."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

from .build import download
from .bundle import SYSTEM_FILES, validate_bundle
from .common import PROFILE_ID, ROOT, Error, load_profile, run, save_json, sha256
from .disk import Ext4Tools, relabel_system
from .install import verify
from .mumu import MuMu
from .profiles import HEX256, matches, repository_file
from .susfs import install_susfs, validate_susfs
from .service_repair import repair_binary


def specification(profile_id: str = PROFILE_ID) -> tuple[dict, dict]:
    profile = load_profile(profile_id)
    spec = json.loads(repository_file(f"profiles/{profile_id}/hardening.json").read_text())
    if spec.get("schema") != 1 or spec.get("base_profile") != profile_id or spec.get("status") not in {"candidate", "verified"}:
        raise Error("Invalid hardening specification")
    if spec.get("policy_path") != "/vendor/etc/selinux/precompiled_sepolicy" or not matches(HEX256, spec.get("policy_before_sha256")):
        raise Error("Hardening must pin the vendor policy input")
    if not matches(HEX256, spec.get("compiled_policy_sha256")):
        raise Error("Hardening must pin the independently inspected compiled policy")
    equivalent = spec.get("equivalent_policy_sha256", [])
    if not isinstance(equivalent, list) or any(not matches(HEX256, value) for value in equivalent):
        raise Error("Equivalent policy serializations require reviewed hashes")
    if not isinstance(spec.get("files"), list) or not spec["files"]:
        raise Error("Hardening file fingerprints are missing")
    seen = set()
    for item in spec["files"]:
        if not isinstance(item, dict):
            raise Error("Invalid system patch entry")
        path = item.get("path")
        if not matches(r"/(?:system|vendor)/[A-Za-z0-9_./@+-]+", path) or ".." in Path(path).parts or path in seen:
            raise Error("Invalid or duplicate system patch path")
        seen.add(path)
        for key in ("before_sha256", "after_sha256"):
            if not matches(HEX256, item.get(key)):
                raise Error("System patches require exact before/after fingerprints")
        repository_file(item.get("patch"))
    if not isinstance(spec.get("binary_repairs", []), list):
        raise Error("Vendor helper repairs must be a list")
    for item in spec.get("binary_repairs", []):
        if not isinstance(item, dict):
            raise Error("Invalid vendor helper repair entry")
        path = item.get("path")
        if not matches(r"/system/bin/[A-Za-z0-9_.-]+", path) or ".." in Path(path).parts or path in seen:
            raise Error("Invalid or duplicate vendor helper path")
        seen.add(path)
        if any(not matches(HEX256, item.get(key)) for key in ("before_sha256", "after_sha256")):
            raise Error("Vendor helper repairs require exact before/after hashes")
        if not matches(r"[A-Za-z0-9_.-]+", item.get("service")):
            raise Error("Vendor helper repair requires its exact init service")
        repository_file(item.get("patch"))
    repository_file(spec.get("policy_rules"))
    if set(spec.get("boot_files", {})) != {"labels.sh", "guard.sh", "mark-boot.sh", "ksu-mumu-policy.rc"}:
        raise Error("Unexpected hardening boot file set")
    for path in spec["boot_files"].values():
        repository_file(path)
    services = spec.get("required_services")
    if not isinstance(services, list) or not services or len(set(services)) != len(services) or any(
            not matches(r"[A-Za-z0-9_.-]+", name) for name in services):
        raise Error("Hardening requires an explicit list of persistent core services")
    trees = spec.get("offline_label_trees")
    if not isinstance(trees, list) or not trees or any(not matches(r"/etc/mumu-configs/[A-Za-z0-9_-]+", path) for path in trees):
        raise Error("Invalid offline label tree list")
    for path, context in spec.get("explicit_system_labels", {}).items():
        if not matches(r"/(?:system|vendor)/[A-Za-z0-9_./@+-]+", path) or ".." in Path(path).parts or not matches(r"u:object_r:[A-Za-z0-9_]+:s0", context):
            raise Error("Invalid explicit system label")
    tool = spec.get("policy_tool", {})
    if tool.get("member") != "lib/arm64-v8a/libmagiskpolicy.so" or not matches(HEX256, tool.get("sha256")):
        raise Error("Unexpected policy utility")
    apk = tool.get("apk", {})
    if not isinstance(apk.get("url"), str) or not apk["url"].startswith("https://") or not matches(HEX256, apk.get("sha256")):
        raise Error("Policy utility APK must be checksum pinned")
    return profile, spec


def recipe_hash(spec: dict) -> str:
    # Repository relocation, a new core profile ID, and promotion do not alter
    # the installed policy. Hash content and guest destinations, not host paths.
    functional = {key: value for key, value in spec.items() if key not in {"id", "base_profile", "status"}}
    functional["policy_rules"] = sha256(repository_file(spec["policy_rules"]))
    functional["boot_files"] = {name: sha256(repository_file(path)) for name, path in spec["boot_files"].items()}
    functional["files"] = [{**item, "patch": sha256(repository_file(item["patch"]))} for item in spec["files"]]
    if "binary_repairs" in spec:
        functional["binary_repairs"] = [{**item, "patch": sha256(repository_file(item["patch"]))}
                                        for item in spec["binary_repairs"]]
    return hashlib.sha256(json.dumps(functional, sort_keys=True).encode()).hexdigest()


def apply_text_patch(before: bytes, item: dict, work: Path) -> bytes:
    if hashlib.sha256(before).hexdigest() != item["before_sha256"]:
        raise Error(f"System file differs from the reviewed MuMu version: {item['path']}")
    target = work / "target"
    target.write_bytes(before)
    run(["patch", "--batch", "--fuzz=0", "-p1", "-d", work, "--input", repository_file(item["patch"])])
    after = target.read_bytes()
    if hashlib.sha256(after).hexdigest() != item["after_sha256"]:
        raise Error(f"Patched file differs from the reviewed result: {item['path']}")
    return after


def verify_hardening(mumu: MuMu, index: int, profile_id: str = PROFILE_ID, *,
                     _expected_recipe: str | None = None, _boot_hashes: dict | None = None,
                     _policy_hash: str | None = None, _binary_hashes: dict | None = None,
                     _file_hashes: dict | None = None, _labels: dict | None = None) -> dict:
    profile, spec = specification(profile_id)
    mumu.validate_app(profile)
    adb = mumu.connect(index)
    current_boot = adb.su("cat /proc/sys/kernel/random/boot_id")
    mode = adb.su("cat /sys/fs/selinux/enforce")
    fallback = adb.shell("getprop sys.ksu_mumu_policy.fallback")
    ready = adb.shell("getprop sys.ksu_mumu_policy.enforcing_ready") == "1"
    completed = adb.su("cat /data/adb/ksu-emulator/enforcing-boot-ok", check=False)
    result = {"instance": index, "kernel_enforcing": mode == "1", "startup_ready": ready,
              "fallback": fallback or None, "boot_id": current_boot,
              "completed_boot_matches": completed == current_boot,
              "verified": mode == "1" and ready and not fallback and completed == current_boot}
    for key, arguments in (("selinux_hiding_enabled", "4"), ("saved_selinux_hiding_enabled", "4 --config")):
        value = re.search(r"^Value: ([01])$", adb.su("/data/adb/ksud feature get " + arguments), re.M)
        result[key] = bool(int(value.group(1))) if value else None
    # Neither hiding value participates in enforcement verification: both are
    # legitimate user choices, and app-facing status may be sanitized.
    # Keep a cryptographic record of which reviewed policy/patch recipe is installed.
    state = json.loads(adb.su("cat /system/etc/ksu-mumu-policy/state.json"))
    # Internal overrides validate an explicitly reviewed previous boot recipe
    # during migration; the CLI always checks the current recipe.
    result["recipe_matches"] = state.get("recipe_sha256") == (_expected_recipe or recipe_hash(spec))
    expected = {item["path"]: (_file_hashes or {}).get(item["path"], item["after_sha256"])
                for item in spec["files"]}
    expected.update({item["path"]: (_binary_hashes or {}).get(item["path"], item["after_sha256"])
                     for item in spec.get("binary_repairs", [])})
    expected[spec["policy_path"]] = _policy_hash or spec["compiled_policy_sha256"]
    for name, source in spec["boot_files"].items():
        remote = "/system/etc/init/" + name if name.endswith(".rc") else "/system/etc/ksu-mumu-policy/" + name
        expected[remote] = (_boot_hashes or {}).get(name, sha256(repository_file(source)))
    sums = adb.su("sha256sum " + " ".join(shlex.quote(path) for path in expected), check=False)
    actual = {parts[1]: parts[0] for line in sums.splitlines() if len(parts := line.split()) == 2}
    accepted_policy = {_policy_hash} if _policy_hash else {
        spec["compiled_policy_sha256"], *spec.get("equivalent_policy_sha256", [])}
    result["installed_files_match"] = all(
        actual.get(path) in accepted_policy if path == spec["policy_path"] else actual.get(path) == digest
        for path, digest in expected.items())
    labels = {**spec["explicit_system_labels"], **(_labels or {}),
              "/dev/vaddress": "u:object_r:mumu_vaddress_device:s0"}
    observed = adb.su("ls -Zd " + " ".join(shlex.quote(path) for path in labels), check=False)
    actual_labels = {parts[-1]: parts[0] for line in observed.splitlines() if len(parts := line.split()) >= 2}
    result["critical_labels_match"] = all(actual_labels.get(path) == context for path, context in labels.items())
    result["init_domain_correct"] = adb.su("cat /proc/1/attr/current").rstrip("\x00") == "u:r:init:s0"
    services = spec["required_services"]
    states = adb.su("; ".join("getprop init.svc." + name for name in services)).splitlines()
    result["service_states"] = dict(zip(services, states))
    result["core_services_running"] = len(states) == len(services) and all(value == "running" for value in states)
    result["verified"] = all((result["verified"], result["recipe_matches"], result["installed_files_match"],
                              result["critical_labels_match"], result["init_domain_correct"], result["core_services_running"]))
    return result


def wait_hardening(mumu: MuMu, index: int, profile_id: str, timeout: int = 30) -> dict:
    """Android's boot flag precedes the core-service stability observation."""
    deadline = time.monotonic() + timeout
    while True:
        result = verify_hardening(mumu, index, profile_id)
        if result["verified"] or result["fallback"] or time.monotonic() >= deadline:
            return result
        time.sleep(1)


def harden_existing(mumu: MuMu, target: int, core_bundle: Path,
                    susfs_bundle: Path | None = None, experimental: bool = False) -> dict:
    core = validate_bundle(core_bundle.expanduser().resolve())
    profile, spec = specification(core["profile"]["id"])
    if spec["status"] != "verified" and not experimental:
        raise Error("Candidate hardening requires --experimental")
    if susfs_bundle:
        susfs_manifest = validate_susfs(susfs_bundle.expanduser().resolve())
        if susfs_manifest["profile"] != profile:
            raise Error("Core and SUSFS bundles must use the same compatibility profile")
        if susfs_manifest["specification"]["status"] != "verified" and not experimental:
            raise Error("Candidate SUSFS requires --experimental")
    digest = recipe_hash(spec)
    if not verify(mumu, target, root=True, profile_id=profile["id"])["persistent_install_ready"]:
        raise Error("Hardening requires a verified base and authorized Shell")
    adb = mumu.connect(target)
    for name in sorted(SYSTEM_FILES | {"ksu-emulator.rc"}):
        remote = "/system/etc/init/ksu-emulator.rc" if name.endswith(".rc") else "/system/etc/ksu-emulator/" + name
        if adb.su("sha256sum " + remote).split()[0] != core["files"][name]:
            raise Error("Installed core differs from the selected bundle: " + name)
    if adb.su("if [ -e /system/etc/ksu-mumu-policy/state.json ]; then echo installed; fi"):
        result = wait_hardening(mumu, target, profile["id"])
        if not result["verified"]:
            raise Error("An existing hardening recipe differs or is unhealthy; an explicitly reviewed policy migration is required")
        susfs = install_susfs(mumu, target, susfs_bundle, experimental) if susfs_bundle else None
        return {"instance": target, "already_hardened": True, "hardening": result, "susfs": susfs}
    ext4 = Ext4Tools()  # Check prerequisites before stopping an instance.
    if not shutil.which("patch"):
        raise Error("The patch utility is required")
    tool_apk = download(spec["policy_tool"]["apk"], ROOT / ".work/cache")
    with zipfile.ZipFile(tool_apk) as apk:
        policy_tool = apk.read(spec["policy_tool"]["member"])
    if hashlib.sha256(policy_tool).hexdigest() != spec["policy_tool"]["sha256"]:
        raise Error("Policy utility does not match the reviewed binary")
    record_path = ROOT / "out/enhancements" / (uuid.uuid4().hex + ".json")
    record = {"schema": 1, "instance": target,
              "profile": profile["id"], "phase": "preparing", "recipe_sha256": digest}
    save_json(record_path, record)
    print(f"Enhancement record: {record_path}", flush=True)
    parent = ROOT / ".work/hardening"
    parent.mkdir(parents=True, exist_ok=True)
    stage = None
    try:
        with tempfile.TemporaryDirectory(prefix="stage-", dir=parent) as temp:
            work = Path(temp)
            adb = mumu.connect(target)
            if adb.su("if [ -e /system/etc/ksu-mumu-policy ]; then echo conflict; fi"):
                raise Error("This instance already has hardening changes. Use upgrade for a framework-only update; policy migrations require a newly reviewed recipe")
            boot = adb.su("cat /proc/sys/kernel/random/boot_id")
            replacements = {}
            for i, item in enumerate(spec["files"]):
                path = item["path"]
                before = adb.bytes("su -c " + shlex.quote("cat " + shlex.quote(path)))
                replacements[path] = apply_text_patch(before, item, work)
            binaries = {item["path"] for item in spec.get("binary_repairs", [])}
            for item in spec.get("binary_repairs", []):
                before = adb.bytes("su -c " + shlex.quote("cat " + item["path"]))
                replacements[item["path"]] = repair_binary(before, item)
            policy = adb.bytes("su -c " + shlex.quote("cat " + spec["policy_path"]))
            if hashlib.sha256(policy).hexdigest() != spec["policy_before_sha256"]:
                raise Error("Vendor policy differs from the reviewed MuMu image")
            if mumu.connect(target).serial != adb.serial or adb.su("cat /proc/sys/kernel/random/boot_id") != boot or recipe_hash(spec) != digest:
                raise Error("Instance or repair recipe changed during preflight")

            stage = "/data/local/tmp/mumu-policy-" + uuid.uuid4().hex
            # ADB still runs as Shell. Its upload directory must remain writable
            # by that identity while privileged copies go into /system.
            adb.shell("mkdir -m 0700 " + stage)

            def push_bytes(data: bytes, remote: str):
                local = work / "payload"
                local.write_bytes(data)
                adb.push(local, remote)

            push_bytes(policy_tool, stage + "/policy-tool")
            push_bytes(policy, stage + "/original-policy")
            adb.push(repository_file(spec["policy_rules"]), stage + "/policy.rules")
            for remote, expected in ((stage + "/policy-tool", spec["policy_tool"]["sha256"]),
                                     (stage + "/policy.rules", sha256(repository_file(spec["policy_rules"]))),
                                     (stage + "/original-policy", spec["policy_before_sha256"])):
                if adb.su("sha256sum " + remote).split()[0] != expected:
                    raise Error("Staged policy input failed integrity verification")
            adb.su(f"chmod 755 {stage}/policy-tool")
            # Compile from the original vendor input; the live merge preserves
            # KernelSU's runtime policy additions while labels are prepared.
            result = adb.call("shell", "su -c " + shlex.quote(
                f"{stage}/policy-tool --load {stage}/original-policy --apply {stage}/policy.rules --save {stage}/compiled-policy"), check=False)
            diagnostics = result.stderr.decode(errors="replace")
            if result.returncode or re.search(r"error|failed|syntax|does not exist|aborting", diagnostics, re.I):
                raise Error("Policy compilation failed: " + diagnostics[-2000:])
            compiled = adb.bytes("su -c " + shlex.quote("cat " + stage + "/compiled-policy"))
            if not compiled:
                raise Error("Policy compiler produced no policy")
            if hashlib.sha256(compiled).hexdigest() != spec["compiled_policy_sha256"]:
                raise Error("Compiled policy differs from the independently inspected result")
            replacements[spec["policy_path"]] = compiled
            adb.su(f"{stage}/policy-tool --live --apply {stage}/policy.rules")
            adb.su("mount -o remount,rw /system; mkdir -p /system/etc/ksu-mumu-policy")

            def install_file(path: str, data: bytes, mode: str = "0644"):
                remote = stage + "/file"
                push_bytes(data, remote)
                quoted = shlex.quote(path)
                pending = shlex.quote(path + ".ksu-new")
                adb.su(f"set -e; cp {remote} {pending}; chmod {mode} {pending}; mv {pending} {quoted}")
                got = adb.su("sha256sum " + quoted).split()[0]
                if got != hashlib.sha256(data).hexdigest():
                    raise Error(f"Installed file failed readback: {path}")

            for path, data in replacements.items():
                install_file(path, data, "0755" if path in binaries else "0644")
            # Restore ordinary vendor labels. MuMu's protected library trees are
            # verified and repaired separately on the stopped disk below.
            adb.su("restorecon -RF /system", check=False)
            for path, context in spec["explicit_system_labels"].items():
                adb.su("chcon " + shlex.quote(context) + " " + shlex.quote(path))
            for name, source in spec["boot_files"].items():
                if name.endswith(".rc"):
                    continue  # Publish the boot action last.
                install_file("/system/etc/ksu-mumu-policy/" + name, repository_file(source).read_bytes(), "0755")
            state = {"schema": 1, "recipe_sha256": digest, "profile": profile["id"],
                     "installed": {path: hashlib.sha256(data).hexdigest() for path, data in replacements.items()}}
            install_file("/system/etc/ksu-mumu-policy/state.json", (json.dumps(state, indent=2) + "\n").encode())
            install_file("/system/etc/init/ksu-mumu-policy.rc", repository_file(spec["boot_files"]["ksu-mumu-policy.rc"]).read_bytes())
            adb.su("restorecon -RF /system/etc/ksu-mumu-policy; restorecon /system/etc/init/ksu-mumu-policy.rc; sync")
            adb.su("rm -rf " + stage)
            record["phase"] = "guest-files-prepared"
            save_json(record_path, record)
            mumu.stop(target)
            record["offline_labels"] = relabel_system(mumu, target, spec["offline_label_trees"], ext4)
            record["phase"] = "disk-labeled"
            save_json(record_path, record)
        mumu.start(target)
        result = wait_hardening(mumu, target, profile["id"])
        if not result["verified"]:
            raise Error("The instance did not complete a genuinely enforcing boot: " + json.dumps(result))
        if susfs_bundle:
            record["susfs"] = install_susfs(mumu, target, susfs_bundle, experimental)
        record["hardening"] = wait_hardening(mumu, target, profile["id"])
        record["root"] = verify(mumu, target, root=True, profile_id=profile["id"])
        if not record["hardening"]["verified"] or not record["root"]["persistent_install_ready"]:
            raise Error("Combined installation verification failed")
        record["phase"] = "verified"
        save_json(record_path, record)
        return {"instance": target, "record": str(record_path),
                "hardening": record["hardening"], "susfs": record.get("susfs"), "root": record["root"]}
    except Exception as exc:
        if stage:
            try:
                adb.su("rm -rf " + shlex.quote(stage), check=False)
            except (Error, OSError):
                pass
        record.update({"phase": "failed", "error": str(exc)})
        save_json(record_path, record)
        try:
            mumu.stop(target)
        except (Error, OSError) as stop_error:
            raise Error(f"Enhancement failed: {exc}. Stop instance {target}: {stop_error}. Record: {record_path}") from exc
        raise Error(f"Enhancement failed and instance {target} was stopped: {exc}. Record: {record_path}") from exc
