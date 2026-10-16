from __future__ import annotations

import json
import shlex
import uuid
from pathlib import Path

from .bundle import SYSTEM_FILES, validate_bundle
from .common import PROFILE_ID, ROOT, Error, load_profile, save_json
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


def install(mumu: MuMu, index: int, bundle: Path, *, experimental: bool = False) -> dict:
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
    directory = Path(device["bundle_path"]).resolve()
    record_path = ROOT / "out/installations" / (uuid.uuid4().hex + ".json")
    record = {"schema": 1, "instance": index, "profile": profile["id"], "phase": "preparing"}
    save_json(record_path, record)
    mumu.stop(index)
    stage = None
    try:
        print("Preparing the selected instance's private system disk...", flush=True)
        mumu.configure(index, vmRootEnable=True, systemWritable=True)
        adb = mumu.start(index)
        if not (directory / "system.qcow2").is_file():
            raise Error("MuMu did not create a private system disk")
        evidence = probe(adb)
        validate_guest(evidence, profile)
        record["target_matches_profile"] = True
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
        adb.call("install", bundle / "manager.apk", timeout=120)
        # Publish the init action last, after the complete payload and APK exist.
        adb.shell(f"set -eu; cp {stage}/ksu-emulator.rc /system/etc/init/ksu-emulator.rc.new; "
                  "chmod 0644 /system/etc/init/ksu-emulator.rc.new; "
                  f"mv /system/etc/init/ksu-emulator.rc.new /system/etc/init/ksu-emulator.rc; rm -rf {stage}; sync")
        record["phase"] = "installed"
        save_json(record_path, record)
        print("Cold booting to verify KernelSU...", flush=True)
        mumu.stop(index)
        adb = mumu.start(index)
        if adb.shell("getprop sys.ksu_emulator.ready") != "1":
            log = adb.shell("cat /data/adb/ksu-emulator/boot.log", check=False)
            raise Error("KernelSU boot hook did not finish:\n" + log[-2500:])
        info = json.loads(adb.shell("/system/etc/ksu-emulator/ksu-probe"))
        if info.get("version") != profile["ksu_version"] or info.get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("KernelSU control API verification failed")
        record["kernel_api"] = info
        print("Disabling MuMu's vendor root and verifying another cold boot...", flush=True)
        mumu.stop(index)
        mumu.configure(index, vmRootEnable=False)
        adb = mumu.start(index)
        if adb.shell("id -u") != "2000":
            raise Error("MuMu vendor root did not switch off")
        result = verify(mumu, index, profile_id=profile["id"])
        if not result["persistent_install_ready"]:
            raise Error("Persistent KernelSU verification failed")
        record["phase"] = "verified"
        save_json(record_path, record)
        result["record"] = str(record_path)
        return result
    except (Error, OSError, ValueError) as exc:
        if stage:
            try:
                adb.shell("rm -rf " + shlex.quote(stage), check=False)
            except (Error, OSError):
                pass  # Android may already be unreachable; report and stop below.
        record["error"] = str(exc)
        record["phase"] = "failed"
        save_json(record_path, record)
        try:
            mumu.stop(index)
            mumu.configure(index, vmRootEnable=False)
        except (Error, OSError, ValueError) as stop_error:
            raise Error(f"Installation failed: {exc}. Could not stop/disable vendor root: {stop_error}. Record: {record_path}") from exc
        raise Error(f"Installation failed and instance {index} was stopped: {exc}. Record: {record_path}") from exc
