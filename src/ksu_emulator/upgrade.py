"""Update the selected instance in place, without retaining old payloads."""
from __future__ import annotations

import hashlib
import json
import shlex
import uuid
from pathlib import Path

from .bundle import SYSTEM_FILES, validate_bundle
from .common import ROOT, Error, save_json
from .install import verify
from .mumu import MuMu
from .probe import probe, validate_guest
from .profiles import build_settings, status


def upgrade(mumu: MuMu, index: int, old_bundle: Path, new_bundle: Path,
                  experimental: bool = False) -> dict:
    old_bundle, new_bundle = old_bundle.expanduser().resolve(), new_bundle.expanduser().resolve()
    old, new = validate_bundle(old_bundle), validate_bundle(new_bundle)
    profile = new["profile"]
    if status(profile) != "verified" and not experimental:
        raise Error("Candidate upgrade requires --experimental")
    if old["profile"]["ksu_package"] != profile["ksu_package"]:
        raise Error("Changing root frameworks requires a clean instance; manager identities differ")
    mumu.validate_app(profile)
    target = index
    settings = mumu.settings(index)
    if settings.get("systemFilePermissionType") != 1 or settings.get("vmRootEnable"):
        raise Error("Upgrade requires the installed private system disk (Writable) and vendor root disabled")
    record_path = ROOT / "out/upgrades" / (uuid.uuid4().hex + ".json")
    record = {"schema": 1, "kind": "in-place-upgrade", "phase": "preparing", "instance": index, "old_profile": old["profile"], "new_profile": profile}
    save_json(record_path, record)
    print(f"Upgrade record: {record_path}; updating instance {target} in place.", flush=True)
    stage = pending = None
    try:
        adb = mumu.start(target)
        if adb.su("id -u") != "0":
            raise Error("Authorize Shell in the selected instance's KernelSU Manager before upgrading")
        validate_guest(probe(adb, root=True), profile, require_bootstrap_root=False)
        remote = "/system/etc/ksu-emulator"
        # Refuse to overwrite a different installation or hand-edited payload.
        for file in sorted(SYSTEM_FILES | {"ksu-emulator.rc"}):
            path = "/system/etc/init/ksu-emulator.rc" if file.endswith(".rc") else remote + "/" + file
            actual = adb.su("sha256sum " + shlex.quote(path)).split()[0]
            if actual != old["files"][file]:
                raise Error(f"Installed file differs from --from-bundle: {file}")
        package = profile["ksu_package"]
        installed = adb.shell("pm path " + package).splitlines()
        if len(installed) != 1 or not installed[0].startswith("package:/"):
            raise Error("Expected one installed Manager APK matching --from-bundle")
        apk = adb.bytes("su -c " + shlex.quote("cat " + shlex.quote(installed[0][8:])))
        if hashlib.sha256(apk).hexdigest() != old["files"]["manager.apk"]:
            raise Error("Installed Manager APK differs from --from-bundle")
        if mumu.connect(target).serial != adb.serial:
            raise Error("Instance ADB identity changed before installation")
        hardened = adb.su("if [ -e /system/etc/ksu-mumu-policy/state.json ]; then echo installed; fi") == "installed"
        if hardened:
            from .hardening import wait_hardening
            from .startup import migrate_hardening_startup
            record["startup_migration"] = migrate_hardening_startup(mumu, index, profile["id"])
        suffix = uuid.uuid4().hex
        stage = "/data/local/tmp/ksu-upgrade-" + suffix
        pending = remote + "-pending-" + suffix
        adb.shell("mkdir -m 0700 " + stage)
        adb.su("mount -o remount,rw /system; mkdir " + pending)
        for file in sorted(SYSTEM_FILES | {"ksu-emulator.rc"}):
            adb.push(new_bundle / file, stage + "/" + file)
        command = "set -eu; " + "; ".join(f"cp {stage}/{f} {pending}/{f}" for f in sorted(SYSTEM_FILES))
        command += f"; chmod 0755 {pending}/ksud {pending}/ksu-probe {pending}/boot.sh"
        command += f"; chmod 0644 {pending}/kernelsu.ko {pending}/payload.sha256"
        command += f"; cd {pending}; sha256sum -c payload.sha256"
        adb.su(command)
        # Android enforces same-package signing continuity for -r.
        adb.call("install", "-r", new_bundle / "manager.apk", timeout=120)
        # Publish individual checked files; preserve the platform compatibility helper.
        publish = "; ".join(f"mv {pending}/{file} {remote}/{file}" for file in sorted(SYSTEM_FILES))
        adb.su(f"set -eu; {publish}; rmdir {pending}; "
                  f"cp {stage}/ksu-emulator.rc /system/etc/init/ksu-emulator.rc.new; "
                  "chmod 0644 /system/etc/init/ksu-emulator.rc.new; "
                  "mv /system/etc/init/ksu-emulator.rc.new /system/etc/init/ksu-emulator.rc; "
                  f"restorecon -RF {remote}; restorecon /system/etc/init/ksu-emulator.rc; rm -rf {stage}; sync")
        record["phase"] = "installed"
        save_json(record_path, record)
        mumu.stop(target)
        adb = mumu.start(target)
        if hardened and not wait_hardening(mumu, target, profile["id"])["verified"]:
            raise Error("Enforcing service checks failed after the first update boot")
        api = json.loads(adb.su(remote + "/ksu-probe"))
        if api.get("version") != profile["ksu_version"] or api.get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("New kernel control API does not match the candidate")
        mumu.stop(target)
        mumu.configure(target, vmRootEnable=False)
        adb = mumu.start(target)
        if adb.shell("id -u") != "2000":
            raise Error("Vendor root did not switch off in the instance")
        if hardened and not wait_hardening(mumu, target, profile["id"])["verified"]:
            raise Error("Enforcing service checks failed after the second update boot")
        result = verify(mumu, target, root=True, profile_id=profile["id"])
        if not result["persistent_install_ready"]:
            raise Error("Instance did not complete KernelSU startup")
        record.update({"phase": "boot-verified", "kernel_api": api, "verification": result})
        save_json(record_path, record)
        return {"upgraded_instance": target, "record": str(record_path),
                "profile_status": status(profile), "verification": result,
                "next_step": "Check Manager, approved and denied root, required modules/apps, and cold boots after updating"}
    except Exception as exc:
        if stage:
            try:
                adb.su("rm -rf " + shlex.quote(stage) + " " + shlex.quote(pending), check=False)
            except (Error, OSError):
                pass
        record.update({"phase": "failed", "error": str(exc)})
        save_json(record_path, record)
        try:
            mumu.stop(target)
        except (Error, OSError) as stop_error:
            raise Error(f"Instance {target} upgrade failed: {exc}. Stop it manually: {stop_error}. Record: {record_path}") from exc
        raise Error(f"Instance {target} upgrade failed and was stopped: {exc}. Record: {record_path}") from exc
