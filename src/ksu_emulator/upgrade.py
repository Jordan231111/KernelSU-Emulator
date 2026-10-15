"""Upgrade a separate clone; retain the complete original as the recovery path."""
from __future__ import annotations

import hashlib
import json
import shlex
import uuid
from pathlib import Path

from .bundle import SYSTEM_FILES, validate_bundle
from .common import ROOT, Error, save_json
from .install import verify
from .maintenance import clone_lab
from .mumu import MuMu
from .probe import probe, validate_guest
from .profiles import build_settings, status


def upgrade_clone(mumu: MuMu, index: int, old_bundle: Path, new_bundle: Path, name: str,
                  experimental: bool = False) -> dict:
    old_bundle, new_bundle = old_bundle.expanduser().resolve(), new_bundle.expanduser().resolve()
    old, new = validate_bundle(old_bundle), validate_bundle(new_bundle)
    profile = new["profile"]
    if status(profile) != "verified" and not experimental:
        raise Error("Candidate upgrade requires --experimental; it will only change a new clone")
    if old["profile"]["ksu_package"] != profile["ksu_package"]:
        raise Error("Changing root frameworks requires a clean instance; manager identities differ")
    mumu.validate_app(profile)
    source = mumu.info(index)
    clone = clone_lab(mumu, index, name)
    target = clone["index"]
    receipt_path = ROOT / "out/upgrades" / (uuid.uuid4().hex + ".json")
    receipt = {"schema": 1, "kind": "clone-upgrade", "phase": "cloned", "source": source,
               "clone": clone, "old_profile": old["profile"], "new_profile": profile}
    save_json(receipt_path, receipt)
    print(f"Upgrade record: {receipt_path}\nOriginal instance {index} is the recovery copy; upgrading clone {target}.", flush=True)
    try:
        mumu.configure(target, vmRootEnable=False, systemWritable=True)
        adb = mumu.start(target)
        if adb.su("id -u") != "0":
            raise Error("Authorize Shell in the source instance's KernelSU Manager before upgrading")
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
            raise Error("Clone ADB identity changed before installation")
        suffix = uuid.uuid4().hex
        stage = "/data/local/tmp/ksu-upgrade-" + suffix
        pending = remote + "-pending-" + suffix
        previous = remote + "-previous-" + suffix
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
        adb.su(f"set -eu; mv {remote} {previous}; mv {pending} {remote}; "
                  f"cp {stage}/ksu-emulator.rc /system/etc/init/ksu-emulator.rc.new; "
                  "chmod 0644 /system/etc/init/ksu-emulator.rc.new; "
                  "mv /system/etc/init/ksu-emulator.rc.new /system/etc/init/ksu-emulator.rc; "
                  f"restorecon -RF {remote}; restorecon /system/etc/init/ksu-emulator.rc; sync")
        receipt["phase"] = "installed"
        save_json(receipt_path, receipt)
        mumu.stop(target)
        adb = mumu.start(target)
        api = json.loads(adb.su(remote + "/ksu-probe"))
        if api.get("version") != profile["ksu_version"] or api.get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("New kernel control API does not match the candidate")
        mumu.stop(target)
        mumu.configure(target, vmRootEnable=False)
        adb = mumu.start(target)
        if adb.shell("id -u") != "2000":
            raise Error("Vendor root did not switch off in the clone")
        result = verify(mumu, target, root=True, profile_id=profile["id"])
        if not result["persistent_install_ready"]:
            raise Error("Clone did not complete KernelSU startup")
        adb.su(f"mount -o remount,rw /system; rm -rf {previous} {stage}; sync")
        receipt.update({"phase": "boot-verified", "kernel_api": api, "verification": result})
        save_json(receipt_path, receipt)
        return {"source_instance": index, "upgraded_instance": target, "record": str(receipt_path),
                "profile_status": status(profile), "verification": result,
                "next_step": "Check Manager, approved and denied root, required modules/apps, and cold boots before using the clone as your main instance"}
    except Exception as exc:
        receipt.update({"phase": "failed", "error": str(exc)})
        save_json(receipt_path, receipt)
        try:
            mumu.stop(target)
        except (Error, OSError) as stop_error:
            raise Error(f"Clone {target} upgrade failed: {exc}. Stop it manually: {stop_error}. Original {index} is preserved. Record: {receipt_path}") from exc
        raise Error(f"Clone {target} upgrade failed and was stopped: {exc}. Original {index} is preserved. Record: {receipt_path}") from exc
