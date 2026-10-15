from __future__ import annotations

import json
import shlex
import shutil
import time
import uuid
from pathlib import Path

from .bundle import SYSTEM_FILES, validate_bundle
from .common import PROFILE_ID, ROOT, Error, load_profile, run, save_json, sha256
from .mumu import MuMu
from .probe import probe, validate_guest
from .profiles import build_settings, status


def verify(mumu: MuMu, index: int, root: bool = False, profile_id: str = PROFILE_ID) -> dict:
    profile = load_profile(profile_id)
    mumu.validate_app(profile)
    adb = mumu.connect(index)
    evidence = probe(adb, root=root)
    loaded = any(line.startswith("kernelsu ") for line in evidence["kernel_modules"].splitlines())
    evidence["kernel_module_listed"] = loaded
    try:
        evidence["kernel_api"] = json.loads(adb.shell("/system/etc/ksu-emulator/ksu-probe"))
    except (Error, ValueError) as exc:
        evidence["kernel_api_error"] = str(exc)
    api = evidence.get("kernel_api", {})
    api_matches = isinstance(api, dict) and api.get("version") == profile["ksu_version"] and api.get("uapi") == build_settings(profile)["uapi_version"]
    evidence["profile"] = profile_id
    evidence["target_matches_profile"] = all(evidence.get(key) == profile[key] for key in
        ("kernel_release", "kernel_version", "architecture", "android_version", "config_gz_sha256"))
    # An unapproved Shell cannot get a control descriptor. Preserve verification
    # of a clean installation before its owner grants Shell root. Hidden modules
    # require the real control protocol through an authorized identity.
    kernel_present = api_matches or (loaded and "kernel_api" not in evidence)
    evidence["persistent_install_ready"] = evidence["installer_ready"] == "1" and kernel_present and evidence["target_matches_profile"]
    evidence["privileged_verification_required"] = not loaded and not api_matches
    if root:
        evidence["root_test"] = adb.su("id; /data/adb/ksud debug version")
        if "uid=0(root)" not in evidence["root_test"] or f"Kernel Version: {profile['ksu_version']}" not in evidence["root_test"]:
            raise Error("KernelSU root verification failed; authorize Shell in KernelSU Manager first")
        evidence["kernel_api"] = json.loads(adb.su("/system/etc/ksu-emulator/ksu-probe"))
        if not isinstance(evidence["kernel_api"], dict) or evidence["kernel_api"].get("version") != profile["ksu_version"] or evidence["kernel_api"].get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("KernelSU control API does not match the selected profile")
        evidence["persistent_install_ready"] = evidence["installer_ready"] == "1" and evidence["target_matches_profile"]
        evidence["privileged_verification_required"] = False
    return evidence


def install(mumu: MuMu, index: int, bundle: Path, *, keep_vendor_root: bool = False, experimental: bool = False) -> dict:
    bundle = bundle.expanduser().resolve()
    manifest = validate_bundle(bundle)
    profile = manifest["profile"]
    if status(profile) != "verified":
        if not experimental:
            raise Error("Candidate bundles require --experimental and a registered laboratory instance")
        from .maintenance import require_lab
        require_lab(mumu, index)
    mumu.validate_app(profile)
    device = mumu.info(index)
    if device["state"] not in {"running", "stopped"}:
        raise Error("Wait for the selected MuMu instance to finish starting/stopping")
    settings = mumu.settings(index)
    mode = settings.get("systemFilePermissionType", 0)
    if mode not in {0, 1}:
        raise Error(f"Untested MuMu system disk mode: {mode}")
    if not shutil.which("qemu-img"):
        raise Error("qemu-img is required for a self-contained disk backup")
    directory = Path(device["bundle_path"]).resolve()
    backup = ROOT / "out/backups" / f"instance-{index}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    backup.mkdir(parents=True, mode=0o700)
    receipt_path = backup / "receipt.json"
    receipt = {
        "schema": 2, "instance": index, "bundle_path": str(directory), "phase": "preparing",
        "was_running": device["state"] == "running", "vendor_root_before": bool(settings.get("vmRootEnable", False)),
        "writable_before": mode == 1, "system_before": (directory / "system.qcow2").is_file(),
        "system_metadata_before": (directory / "system.qcow2.json").is_file(),
        "manager_install_attempted": False, "manager_package": profile["ksu_package"],
    }
    save_json(backup / "profile.json", profile)
    receipt["profile_sha256"] = sha256(backup / "profile.json")
    save_json(receipt_path, receipt)
    print(f"Recovery receipt: {receipt_path}", flush=True)
    mumu.stop(index)
    if receipt["system_before"]:
        # Flatten backing files so recovery does not depend on a future app update.
        run(["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", directory / "system.qcow2", backup / "system.qcow2"], timeout=600)
        receipt["system_backup_sha256"] = sha256(backup / "system.qcow2")
    receipt["phase"] = "backed_up"
    save_json(receipt_path, receipt)
    try:
        print("Preparing the selected instance's private system disk...", flush=True)
        mumu.configure(index, vmRootEnable=True, systemWritable=True)
        adb = mumu.start(index)
        if not (directory / "system.qcow2").is_file():
            raise Error("MuMu did not create a private system disk")
        evidence = probe(adb)
        validate_guest(evidence, profile)
        save_json(backup / "probe-before.json", evidence)
        if adb.shell("pm path " + profile["ksu_package"], check=False):
            raise Error("KernelSU Next Manager is already installed; use a clean instance")
        conflict = adb.shell(
            "if [ -e /data/adb/ksud ] || [ -e /data/adb/magisk ] || "
            "[ -e /system/etc/ksu-emulator ] || [ -e /system/etc/init/ksu-emulator.rc ]; then echo conflict; fi"
        )
        if conflict or any(line.startswith("kernelsu ") for line in evidence["kernel_modules"].splitlines()):
            raise Error("Existing root framework detected; use a clean instance")
        # Check that MuMu still maps this exact running device before writing.
        if mumu.connect(index).serial != adb.serial:
            raise Error("MuMu changed the selected instance's ADB port during installation")
        stage = "/data/local/tmp/ksu-emulator-" + uuid.uuid4().hex
        adb.shell("mkdir " + shlex.quote(stage))
        for name in sorted(SYSTEM_FILES | {"ksu-emulator.rc"}):
            adb.push(bundle / name, stage + "/" + name)
        remote = "/system/etc/ksu-emulator"
        command = "set -eu; mkdir " + remote + "; "
        command += "; ".join(f"cp {shlex.quote(stage + '/' + name)} {remote}/{name}" for name in sorted(SYSTEM_FILES))
        command += f"; chmod 0755 {remote}/ksud {remote}/ksu-probe {remote}/boot.sh"
        command += f"; chmod 0644 {remote}/kernelsu.ko {remote}/payload.sha256"
        command += f"; cd {remote}; sha256sum -c payload.sha256"
        adb.shell(command)
        receipt["manager_install_attempted"] = True
        save_json(receipt_path, receipt)
        adb.call("install", bundle / "manager.apk", timeout=120)
        # Publish the init action last, after the complete payload and APK exist.
        adb.shell(f"set -eu; cp {stage}/ksu-emulator.rc /system/etc/init/ksu-emulator.rc.new; "
                  "chmod 0644 /system/etc/init/ksu-emulator.rc.new; "
                  "mv /system/etc/init/ksu-emulator.rc.new /system/etc/init/ksu-emulator.rc; sync")
        receipt["phase"] = "installed"
        save_json(receipt_path, receipt)
        print("Cold booting to verify KernelSU...", flush=True)
        mumu.stop(index)
        adb = mumu.start(index)
        if adb.shell("getprop sys.ksu_emulator.ready") != "1":
            log = adb.shell("cat /data/adb/ksu-emulator/boot.log", check=False)
            raise Error("KernelSU boot hook did not finish:\n" + log[-2500:])
        info = json.loads(adb.shell("/system/etc/ksu-emulator/ksu-probe"))
        if info.get("version") != profile["ksu_version"] or info.get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("KernelSU control API verification failed")
        receipt["kernel_api"] = info
        if not keep_vendor_root:
            print("Disabling MuMu's vendor root and verifying another cold boot...", flush=True)
            mumu.stop(index)
            mumu.configure(index, vmRootEnable=False)
            adb = mumu.start(index)
            if adb.shell("id -u") != "2000":
                raise Error("MuMu vendor root did not switch off")
        result = verify(mumu, index, profile_id=profile["id"])
        if not result["persistent_install_ready"]:
            raise Error("Persistent KernelSU verification failed")
        receipt["phase"] = "verified"
        save_json(receipt_path, receipt)
        result["recovery_receipt"] = str(receipt_path)
        return result
    except (Error, OSError, ValueError) as exc:
        receipt["phase"] = "failed"
        save_json(receipt_path, receipt)
        try:
            restore(mumu, receipt_path)
        except (Error, OSError, ValueError) as rollback:
            raise Error(f"Installation failed: {exc}\nRecovery failed: {rollback}\nReceipt: {receipt_path}") from exc
        raise Error(f"Installation failed and system/settings were restored: {exc}\nReceipt: {receipt_path}") from exc


def restore(mumu: MuMu, receipt_path: Path) -> dict:
    receipt_path = receipt_path.expanduser().resolve()
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("schema") not in {1, 2} or receipt.get("phase") == "preparing":
        raise Error("Receipt has no completed backup")
    if receipt.get("phase") == "restored":
        return {"restored": True, "instance": receipt["instance"]}
    index = receipt["instance"]
    device = mumu.info(index)
    directory = Path(device["bundle_path"]).resolve()
    if directory != Path(receipt["bundle_path"]).resolve():
        raise Error("Instance identity differs from the recovery receipt")
    source = receipt_path.parent / "system.qcow2"
    if receipt["system_before"] and (not source.is_file() or sha256(source) != receipt.get("system_backup_sha256")):
        raise Error("System disk backup is missing or its checksum changed")
    package = receipt.get("manager_package")
    if receipt["schema"] == 1:
        if package != "com.rifsxd.ksunext":
            raise Error("Unexpected manager package in legacy receipt")
    else:
        snapshot = receipt_path.parent / "profile.json"
        if sha256(snapshot) != receipt.get("profile_sha256") or json.loads(snapshot.read_text()).get("ksu_package") != package:
            raise Error("Recovery profile identity does not match the receipt")
        import re
        if not isinstance(package, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package):
            raise Error("Invalid manager package in receipt")
    mumu.stop(index)
    if receipt["system_before"]:
        target = directory / "system.qcow2.restore"
        shutil.copyfile(source, target)
        if sha256(target) != receipt["system_backup_sha256"]:
            raise Error("Restored system copy failed checksum verification")
        target.replace(directory / "system.qcow2")
    else:
        (directory / "system.qcow2").unlink(missing_ok=True)
        if not receipt["system_metadata_before"]:
            (directory / "system.qcow2.json").unlink(missing_ok=True)
    mumu.configure(index, vmRootEnable=receipt["vendor_root_before"], systemWritable=receipt["writable_before"])
    if receipt["manager_install_attempted"] or receipt["was_running"]:
        adb = mumu.start(index)
        if receipt["manager_install_attempted"] and adb.shell("pm path " + package, check=False):
            adb.call("uninstall", package, timeout=120)
        if not receipt["was_running"]:
            mumu.stop(index)
    receipt["phase"] = "restored"
    save_json(receipt_path, receipt)
    return {"restored": True, "instance": index, "retained": "/data/adb (modules and logs)"}
