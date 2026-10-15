from __future__ import annotations

import gzip
import hashlib

from .common import Error
from .mumu import Adb


def probe(adb: Adb) -> dict:
    result = {"serial": adb.serial}
    for key, command in {
        "kernel_release": "uname -r", "kernel_version": "uname -v", "architecture": "uname -m",
        "android_version": "getprop ro.build.version.release", "adb_uid": "id -u",
        "selinux": "getenforce", "boot_completed": "getprop sys.boot_completed",
        "installer_ready": "getprop sys.ksu_emulator.ready",
    }.items():
        result[key] = adb.shell(command)
    try:
        config_bytes = adb.bytes("cat /proc/config.gz")
        config = gzip.decompress(config_bytes).decode()
        result["config_gz_sha256"] = hashlib.sha256(config_bytes).hexdigest()
        flags = {}
        for line in config.splitlines():
            if line.startswith("CONFIG_") and "=" in line:
                key, value = line.split("=", 1)
                flags[key] = value
        result["config"] = {key: flags.get(key, "n") for key in (
            "CONFIG_MODULES", "CONFIG_MODVERSIONS", "CONFIG_MODULE_SIG_FORCE", "CONFIG_KPROBES",
            "CONFIG_KALLSYMS", "CONFIG_RANDOMIZE_BASE", "CONFIG_SECURITY_WRITABLE_HOOKS",
        )}
    except (Error, ValueError, OSError) as exc:
        result["config_error"] = str(exc)
    result["kernel_modules"] = adb.shell("cat /proc/modules", check=False)
    return result


def validate_guest(evidence: dict, profile: dict) -> None:
    for key in ("kernel_release", "kernel_version", "architecture", "android_version", "config_gz_sha256"):
        if evidence.get(key) != profile[key]:
            raise Error(f"Guest {key} does not match the tested profile: {evidence.get(key)!r}")
    if evidence["adb_uid"] != "0":
        raise Error("Bootstrap ADB root is required for installation")
    if evidence.get("config", {}).get("CONFIG_MODULES") != "y":
        raise Error("Kernel cannot load modules")
    if evidence["config"].get("CONFIG_MODULE_SIG_FORCE") == "y":
        raise Error("Kernel requires signed modules")
