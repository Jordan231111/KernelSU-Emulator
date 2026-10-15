"""Version-locked MuMu SELinux repairs, always performed on an upgrade clone."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from .build import download
from .bundle import validate_bundle
from .common import PROFILE_ID, ROOT, Error, load_profile, run, save_json, sha256
from .disk import Ext4Tools, relabel_system_clone
from .install import verify
from .maintenance import require_lab
from .mumu import MuMu
from .profiles import HEX256, matches, repository_file
from .susfs import install_susfs, validate_susfs
from .upgrade import upgrade_clone


def specification(profile_id: str = PROFILE_ID) -> tuple[dict, dict]:
    profile = load_profile(profile_id)
    spec = json.loads(repository_file(f"profiles/{profile_id}/hardening.json").read_text())
    if spec.get("schema") != 1 or spec.get("base_profile") != profile_id or spec.get("status") not in {"candidate", "verified"}:
        raise Error("Invalid hardening specification")
    if spec.get("policy_path") != "/vendor/etc/selinux/precompiled_sepolicy" or not matches(HEX256, spec.get("policy_before_sha256")):
        raise Error("Hardening must pin the vendor policy input")
    if not matches(HEX256, spec.get("compiled_policy_sha256")):
        raise Error("Hardening must pin the independently inspected compiled policy")
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
    repository_file(spec.get("policy_rules"))
    if set(spec.get("boot_files", {})) != {"labels.sh", "guard.sh", "mark-boot.sh", "ksu-mumu-policy.rc"}:
        raise Error("Unexpected hardening boot file set")
    for path in spec["boot_files"].values():
        repository_file(path)
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


def verify_hardening(mumu: MuMu, index: int, profile_id: str = PROFILE_ID) -> dict:
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
    # Keep a cryptographic record of which reviewed policy/patch recipe is installed.
    state = json.loads(adb.su("cat /system/etc/ksu-mumu-policy/state.json"))
    result["recipe_matches"] = state.get("recipe_sha256") == recipe_hash(spec)
    expected = {item["path"]: item["after_sha256"] for item in spec["files"]}
    expected[spec["policy_path"]] = spec["compiled_policy_sha256"]
    for name, source in spec["boot_files"].items():
        remote = "/system/etc/init/" + name if name.endswith(".rc") else "/system/etc/ksu-mumu-policy/" + name
        expected[remote] = sha256(repository_file(source))
    sums = adb.su("sha256sum " + " ".join(shlex.quote(path) for path in expected), check=False)
    actual = {parts[1]: parts[0] for line in sums.splitlines() if len(parts := line.split()) == 2}
    result["installed_files_match"] = all(actual.get(path) == digest for path, digest in expected.items())
    labels = {**spec["explicit_system_labels"], "/dev/vaddress": "u:object_r:mumu_vaddress_device:s0"}
    observed = adb.su("ls -Zd " + " ".join(shlex.quote(path) for path in labels), check=False)
    actual_labels = {parts[-1]: parts[0] for line in observed.splitlines() if len(parts := line.split()) >= 2}
    result["critical_labels_match"] = all(actual_labels.get(path) == context for path, context in labels.items())
    result["init_domain_correct"] = adb.su("cat /proc/1/attr/current").rstrip("\x00") == "u:r:init:s0"
    result["verified"] = all((result["verified"], result["recipe_matches"], result["installed_files_match"],
                              result["critical_labels_match"], result["init_domain_correct"]))
    return result


def enhance_clone(mumu: MuMu, source_index: int, old_bundle: Path, core_bundle: Path,
                  susfs_bundle: Path | None, name: str, experimental: bool = False) -> dict:
    core = validate_bundle(core_bundle.expanduser().resolve())
    profile, spec = specification(core["profile"]["id"])
    if spec["status"] != "verified" and not experimental:
        raise Error("Candidate hardening requires --experimental; changes will be restricted to a new clone")
    if susfs_bundle:
        susfs_manifest = validate_susfs(susfs_bundle.expanduser().resolve())
        if susfs_manifest["profile"] != profile:
            raise Error("Core and SUSFS bundles must use the same compatibility profile")
        if susfs_manifest["specification"]["status"] != "verified" and not experimental:
            raise Error("Candidate SUSFS requires --experimental")
    ext4 = Ext4Tools()  # Check prerequisites before stopping or cloning an instance.
    if not shutil.which("patch"):
        raise Error("The patch utility is required")
    tool_apk = download(spec["policy_tool"]["apk"], ROOT / ".work/cache")
    with zipfile.ZipFile(tool_apk) as apk:
        policy_tool = apk.read(spec["policy_tool"]["member"])
    if hashlib.sha256(policy_tool).hexdigest() != spec["policy_tool"]["sha256"]:
        raise Error("Policy utility does not match the reviewed binary")
    digest = recipe_hash(spec)
    upgraded = upgrade_clone(mumu, source_index, old_bundle, core_bundle, name, experimental)
    target = upgraded["upgraded_instance"]
    require_lab(mumu, target)
    record_path = ROOT / "out/enhancements" / (uuid.uuid4().hex + ".json")
    record = {"schema": 1, "source_instance": source_index, "instance": target,
              "profile": profile["id"], "phase": "base-upgraded", "recipe_sha256": digest,
              "upgrade_record": upgraded["record"], "recovery": "Use the complete preserved source instance"}
    save_json(record_path, record)
    print(f"Enhancement record: {record_path}", flush=True)
    parent = ROOT / ".work/hardening"
    parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="stage-", dir=parent) as temp:
            work = Path(temp)
            adb = mumu.connect(target)
            if adb.su("if [ -e /system/etc/ksu-mumu-policy ]; then echo conflict; fi"):
                raise Error("This instance already has hardening changes. Use upgrade-clone for a framework-only update; policy migrations require a newly reviewed recipe")
            boot = adb.su("cat /proc/sys/kernel/random/boot_id")
            originals, replacements = {}, {}
            for i, item in enumerate(spec["files"]):
                path = item["path"]
                before = adb.bytes("su -c " + shlex.quote("cat " + shlex.quote(path)))
                originals[path] = before
                replacements[path] = apply_text_patch(before, item, work)
            policy = adb.bytes("su -c " + shlex.quote("cat " + spec["policy_path"]))
            if hashlib.sha256(policy).hexdigest() != spec["policy_before_sha256"]:
                raise Error("Vendor policy differs from the reviewed MuMu image")
            originals[spec["policy_path"]] = policy
            if mumu.connect(target).serial != adb.serial or adb.su("cat /proc/sys/kernel/random/boot_id") != boot or recipe_hash(spec) != digest:
                raise Error("Clone or repair recipe changed during preflight")

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
            adb.su("mount -o remount,rw /system; mkdir -p /system/etc/ksu-mumu-policy/originals; chmod 0700 /system/etc/ksu-mumu-policy/originals")

            def install_file(path: str, data: bytes, mode: str = "0644"):
                remote = stage + "/file"
                push_bytes(data, remote)
                quoted = shlex.quote(path)
                pending = shlex.quote(path + ".ksu-new")
                adb.su(f"set -e; cp {remote} {pending}; chmod {mode} {pending}; mv {pending} {quoted}")
                got = adb.su("sha256sum " + quoted).split()[0]
                if got != hashlib.sha256(data).hexdigest():
                    raise Error(f"Installed file failed readback: {path}")

            saved = {}
            for i, (path, data) in enumerate(originals.items()):
                original = f"/system/etc/ksu-mumu-policy/originals/{i:03d}"
                install_file(original, data, "0600")
                saved[path] = {"path": original, "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in replacements.items():
                install_file(path, data)
            # Restore ordinary vendor labels. MuMu's protected library trees are
            # verified and repaired separately on the stopped disk below.
            adb.su("restorecon -RF /system", check=False)
            for path, context in spec["explicit_system_labels"].items():
                adb.su("chcon " + shlex.quote(context) + " " + shlex.quote(path))
            for name, source in spec["boot_files"].items():
                if name.endswith(".rc"):
                    continue  # Publish the boot action last.
                install_file("/system/etc/ksu-mumu-policy/" + name, repository_file(source).read_bytes(), "0755")
            state = {"schema": 1, "recipe_sha256": digest, "profile": profile["id"], "originals": saved,
                     "installed": {path: hashlib.sha256(data).hexdigest() for path, data in replacements.items()}}
            install_file("/system/etc/ksu-mumu-policy/state.json", (json.dumps(state, indent=2) + "\n").encode())
            install_file("/system/etc/init/ksu-mumu-policy.rc", repository_file(spec["boot_files"]["ksu-mumu-policy.rc"]).read_bytes())
            adb.su("restorecon -RF /system/etc/ksu-mumu-policy; restorecon /system/etc/init/ksu-mumu-policy.rc; sync")
            adb.su("rm -rf " + stage)
            record["phase"] = "guest-files-prepared"
            save_json(record_path, record)
            mumu.stop(target)
            record["offline_labels"] = relabel_system_clone(mumu, target, spec["offline_label_trees"], ext4)
            record["phase"] = "disk-labeled"
            save_json(record_path, record)
        mumu.start(target)
        result = verify_hardening(mumu, target, profile["id"])
        if not result["verified"]:
            raise Error("The clone did not complete a genuinely enforcing boot: " + json.dumps(result))
        if susfs_bundle:
            record["susfs"] = install_susfs(mumu, target, susfs_bundle, experimental)
        record["hardening"] = verify_hardening(mumu, target, profile["id"])
        record["root"] = verify(mumu, target, root=True, profile_id=profile["id"])
        if not record["hardening"]["verified"] or not record["root"]["persistent_install_ready"]:
            raise Error("Combined installation verification failed")
        record["phase"] = "verified"
        save_json(record_path, record)
        return {"source_instance": source_index, "enhanced_instance": target, "record": str(record_path),
                "hardening": record["hardening"], "susfs": record.get("susfs"), "root": record["root"]}
    except Exception as exc:
        record.update({"phase": "failed", "error": str(exc)})
        save_json(record_path, record)
        try:
            mumu.stop(target)
        except (Error, OSError) as stop_error:
            raise Error(f"Enhancement failed: {exc}. Stop clone {target}: {stop_error}. Original {source_index} is preserved. Record: {record_path}") from exc
        raise Error(f"Enhancement failed and clone {target} was stopped: {exc}. Original {source_index} is preserved. Record: {record_path}") from exc
