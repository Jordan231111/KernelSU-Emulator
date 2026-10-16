"""Fingerprint-checked removal of MuMu's legacy root providers."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import stat
import tempfile
import uuid
from pathlib import Path

from .common import ROOT, PROFILE_ID, Error, load_profile, run, save_json, sha256
from .disk import Ext4Tools, partition_bounds
from .hardening import apply_text_patch, wait_hardening
from .mumu import MuMu
from .profiles import HEX256, matches, repository_file


def specification(profile_id: str):
    profile = load_profile(profile_id)
    spec = json.loads(repository_file(f"profiles/{profile_id}/vendor-cleanup.json").read_text())
    if spec.get("schema") != 1 or spec.get("base_profile") != profile_id or spec.get("status") not in {"candidate", "verified"}:
        raise Error("Invalid vendor cleanup specification")
    if {item.get("path") for item in spec.get("files", [])} != {"/system/etc/init.sh", "/system/etc/init/hw/init.comm.rc"}:
        raise Error("Unexpected vendor startup file set")
    for item in spec["files"]:
        if not all(matches(HEX256, item.get(key)) for key in ("before_sha256", "after_sha256")):
            raise Error("Vendor startup files must be fingerprinted")
        repository_file(item["patch"])
    allowed = {"/xbin/mu_bak", "/bin/serial_console"}
    if {item.get("path") for item in spec.get("remove_files", [])} != allowed:
        raise Error("Unexpected vendor helper removal list")
    for item in spec["remove_files"]:
        if not matches(HEX256, item.get("sha256")):
            raise Error("Vendor helper fingerprint missing")
    if spec.get("optional_aliases") != ["/xbin/su", "/bin/su", "/bin/VBoxShell"]:
        raise Error("Unexpected vendor alias list")
    if spec.get("must_be_absent") != ["/app/SuperUser", "/etc/init/magisk.rc", "/etc/init/magisk", "/bin/magisk", "/xbin/magisk"]:
        raise Error("Unexpected root framework conflict list")
    if spec.get("companion_package") != "com.netease.nemu_vapi_android.nemu" or not matches(HEX256, spec.get("companion_apk_sha256")):
        raise Error("The vendor companion must be explicitly fingerprinted")
    if spec.get("disabled_receiver") != "com.netease.nemu_vapi_android.nemu/com.netease.nemu_vapi_android.receiver.LaunchReceiver":
        raise Error("Unexpected vendor receiver")
    expected = {"/system/etc/ksu-emulator/platform-service.sh", "/system/etc/init/ksu-mumu-platform.rc"}
    if set(spec.get("boot_files", {})) != expected:
        raise Error("Unexpected vendor compatibility startup files")
    for source in spec["boot_files"].values():
        repository_file(source)
    return profile, spec


def verify_vendor_cleanup(mumu: MuMu, index: int, profile_id: str = PROFILE_ID) -> dict:
    profile, spec = specification(profile_id)
    mumu.validate_app(profile)
    adb = mumu.connect(index)
    expected = {item["path"]: item["after_sha256"] for item in spec["files"]}
    expected.update({path: sha256(repository_file(source)) for path, source in spec["boot_files"].items()})
    raw = adb.su("sha256sum " + " ".join(shlex.quote(path) for path in expected), check=False)
    actual = {parts[1]: parts[0] for line in raw.splitlines() if len(parts := line.split()) == 2}
    process_names = {line.split()[-1] for line in adb.su("ps -A").splitlines() if line.split()}
    forbidden = {"mu_bak", "serial_console", "VBoxShell", "su_daemon", "daemonsu", "magiskd", "apd"}
    # Zygisk/Vector can be ordinary KernelSU add-ons. Their process names do
    # not establish that Magisk or a vendor root provider is still installed.
    injection = {"zygisk-ptrace64", "zygisk-ptrace32", "zygiskd64", "zygiskd32", "vectord", "lspd"}
    helpers = ["/system" + item["path"] for item in spec["remove_files"]]
    present = adb.su("; ".join(f"if [ -e {path} ]; then echo {path}; fi" for path in helpers), check=False).splitlines()
    package = adb.su("dumpsys package " + spec["companion_package"])
    disabled = re.search(r"disabledComponents:\s*\n((?:\s{8,}.*\n?)*)", package)
    receiver_disabled = bool(disabled and spec["disabled_receiver"].split("/", 1)[1] in disabled.group(1))
    service_dump = adb.su("dumpsys activity services " + spec["companion_package"])
    api_service = re.search(r"\* ServiceRecord\{[^\n]*com\.netease\.nemu_vapi_android\.service\.ApiService\}\n(.*?)(?=\n  \* ServiceRecord|\n  Connection bindings|\Z)", service_dump, re.S)
    api_running = bool(api_service and "app=ProcessRecord{" in api_service.group(1))
    root_services = {name: adb.shell("getprop init.svc." + name) for name in ("su_daemon", "VBoxShell")}
    result = {"instance": index, "files_match": all(actual.get(path) == digest for path, digest in expected.items()),
              "old_root_processes": sorted(process_names & forbidden), "vendor_helpers_present": present,
              "injection_module_processes": sorted(process_names & injection),
              "legacy_receiver_disabled": receiver_disabled,
              "platform_api_running": api_running, "vendor_root_services": root_services,
              "platform_api_ready": adb.shell("getprop sys.ksu_mumu.platform_ready") == "1",
              "vendor_root_setting_disabled": mumu.settings(index).get("vmRootEnable") is False}
    result["verified"] = all((result["files_match"], not result["old_root_processes"], not present,
                               receiver_disabled, api_running, not any(root_services.values()), result["platform_api_ready"], result["vendor_root_setting_disabled"]))
    return result


def clean_vendor_root(mumu: MuMu, index: int, profile_id: str = PROFILE_ID,
                      experimental: bool = False) -> dict:
    profile, spec = specification(profile_id)
    if spec["status"] != "verified" and not experimental:
        raise Error("Candidate vendor cleanup requires --experimental")
    mumu.validate_app(profile)
    ready = verify_vendor_cleanup(mumu, index, profile_id)
    if ready["verified"]:
        return {**ready, "already_clean": True}
    if not wait_hardening(mumu, index, profile_id)["verified"]:
        raise Error("Install and verify the matching enforcing configuration before vendor cleanup")
    adb = mumu.connect(index)
    apk_paths = adb.su("pm path " + spec["companion_package"]).splitlines()
    if len(apk_paths) != 1 or not apk_paths[0].startswith("package:/"):
        raise Error("Expected one fingerprinted vendor companion APK")
    apk = adb.bytes("su -c " + shlex.quote("cat " + shlex.quote(apk_paths[0][8:])))
    if hashlib.sha256(apk).hexdigest() != spec["companion_apk_sha256"]:
        raise Error("Vendor companion changed; review its root receiver before cleanup")
    tools = Ext4Tools()
    if not shutil.which("qemu-img"):
        raise Error("qemu-img is required for offline vendor cleanup")
    mumu.stop(index)
    device = mumu.info(index)
    disk = Path(device["bundle_path"]) / "system.qcow2"
    if disk.is_symlink() or not disk.is_file() or disk.stat().st_nlink != 1:
        raise Error("Expected an independent private system disk")
    before_hash = sha256(disk)
    record_path = ROOT / "out/vendor-cleanup" / (uuid.uuid4().hex + ".json")
    record = {"instance": index, "profile": profile_id, "phase": "stopped"}
    save_json(record_path, record)
    parent = ROOT / ".work/vendor-cleanup"
    parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=parent) as tmp:
            work = Path(tmp)
            raw, part, rebuilt = work / "disk.raw", work / "system.ext4", work / "system.qcow2"
            run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw], timeout=600)
            with raw.open("rb") as source:
                offset, size = partition_bounds(source.read(512), raw.stat().st_size)
                source.seek(offset)
                with part.open("wb") as output:
                    remaining = size
                    while remaining:
                        block = source.read(min(8 << 20, remaining))
                        if not block:
                            raise Error("Truncated system disk")
                        output.write(block)
                        remaining -= len(block)
            argument = tools.path(part, work)
            tools.call("e2fsck", ["-fn", argument], work)

            def debug(command, write=False):
                return tools.call("debugfs", (["-w"] if write else []) + ["-R", command, argument], work)

            def local_path(path):
                value = tools.path(path, work)
                return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

            def inode(path):
                result = debug("stat " + path)
                text = result.stdout.decode(errors="replace")
                match = re.search(r"Inode:\s+(\d+)", text)
                if match:
                    return int(match.group(1)), text
                if b"File not found" in result.stderr:
                    return None, text
                raise Error("Cannot inspect filesystem inode: " + path)

            def read(path):
                target = work / "readback"
                target.unlink(missing_ok=True)
                debug("dump " + path + " " + local_path(target))
                if not target.is_file():
                    raise Error("Cannot read filesystem file: " + path)
                return target.read_bytes()

            replacements = {}
            for item in spec["files"]:
                path = item["path"].removeprefix("/system")
                data = read(path)
                if hashlib.sha256(data).hexdigest() == item["after_sha256"]:
                    replacements[path] = data
                else:
                    replacements[path] = apply_text_patch(data, item, work)
            removals = []
            allowed_hashes = {item["sha256"] for item in spec["remove_files"]}
            for item in spec["remove_files"]:
                if inode(item["path"])[0] is not None:
                    if hashlib.sha256(read(item["path"])).hexdigest() != item["sha256"]:
                        raise Error("Vendor root helper differs from the reviewed binary: " + item["path"])
                    removals.append(item["path"])
            for path in spec["optional_aliases"]:
                number, info = inode(path)
                if number is not None:
                    if "Type: symlink" not in info and hashlib.sha256(read(path)).hexdigest() not in allowed_hashes:
                        raise Error("Unrecognized root alias; refusing an unreviewed deletion: " + path)
                    removals.append(path)
            for path in spec["must_be_absent"]:
                if inode(path)[0] is not None:
                    raise Error("Remove the existing root framework before cleanup: " + path)
            for path, source in spec["boot_files"].items():
                replacements[path.removeprefix("/system")] = repository_file(source).read_bytes()
            context = work / "context.bin"
            context.write_bytes(b"u:object_r:system_file:s0\0")
            for path, data in replacements.items():
                staged = work / "replacement"
                staged.write_bytes(data)
                if inode(path)[0] is not None:
                    debug("rm " + path, True)
                debug("write " + local_path(staged) + " " + path, True)
                number = inode(path)[0]
                if number is None:
                    raise Error("Filesystem replacement failed: " + path)
                mode = "0100755" if path.endswith(".sh") else "0100644"
                debug(f"set_inode_field <{number}> mode {mode}", True)
                debug(f"ea_set -f {local_path(context)} <{number}> security.selinux", True)
                if read(path) != data:
                    raise Error("Filesystem replacement readback differs: " + path)
            for path in removals:
                debug("rm " + path, True)
                if inode(path)[0] is not None:
                    raise Error("Vendor helper was not removed: " + path)
            tools.call("e2fsck", ["-fn", argument], work)
            if part.stat().st_size != size:
                raise Error("Filesystem size changed unexpectedly")
            with raw.open("r+b") as destination, part.open("rb") as source:
                destination.seek(offset)
                shutil.copyfileobj(source, destination, 8 << 20)
            run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, rebuilt], timeout=600)
            run(["qemu-img", "check", rebuilt], timeout=180)
            staged = disk.with_name("system.qcow2.cleanup-" + uuid.uuid4().hex)
            try:
                shutil.copyfile(rebuilt, staged)
                if sha256(staged) != sha256(rebuilt) or mumu.info(index)["state"] != "stopped" or sha256(disk) != before_hash:
                    raise Error("Disk or instance changed during cleanup")
                staged.chmod(stat.S_IMODE(disk.stat().st_mode))
                staged.replace(disk)
            finally:
                staged.unlink(missing_ok=True)
        mumu.configure(index, vmRootEnable=False)
        mumu.start(index)
        hardening = wait_hardening(mumu, index, profile_id)
        result = verify_vendor_cleanup(mumu, index, profile_id)
        if not hardening["verified"] or not result["verified"]:
            raise Error("Post-cleanup verification failed: " + json.dumps(result))
        record.update(phase="verified", removed=removals, verification=result)
        save_json(record_path, record)
        return {**result, "record": str(record_path)}
    except Exception as exc:
        record.update(phase="failed", error=str(exc))
        save_json(record_path, record)
        mumu.stop(index)
        raise Error(f"Cleanup failed and instance {index} was stopped: {exc}. Record: {record_path}") from exc
