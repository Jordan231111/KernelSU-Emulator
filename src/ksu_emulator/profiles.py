"""Versioned, explicit build contracts; preserving the original release profile."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .common import PROFILE_ID, ROOT, Error

ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")


def matches(pattern, value) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def repository_file(name: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts:
        raise Error(f"Invalid repository-relative file: {name!r}")
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
        raise Error(f"Recipe file is missing or outside the repository: {name}")
    return path


def status(profile: dict) -> str:
    validation = profile.get("validation", {})
    if not isinstance(validation, dict):
        raise Error("Profile validation must be an object")
    return validation.get("status", "verified" if profile["id"] == PROFILE_ID else "candidate")


def build_settings(profile: dict) -> dict:
    if "build" in profile:
        if not isinstance(profile["build"], dict):
            raise Error("Profile build settings must be an object")
        return profile["build"]
    if profile["id"] != PROFILE_ID:
        raise Error("A new profile needs explicit build settings")
    return {
        "arch": "arm64", "cross_compile": "aarch64-linux-gnu-",
        "local_version": "-android-arm64-gedae1315d023",
        "kernel_config": f"profiles/{PROFILE_ID}/kernel.config",
        "kernel_patches": ["patches/mumu-task-layout.patch"],
        "module_patches": ["patches/kernelsu-next-mumu.patch"],
        "module_directory": "kernel",
        "config": {"CONFIG_KSU": "m", "CONFIG_KSU_DEBUG": "n", "CONFIG_KSU_SYSCALL_TABLE_HOOK": "y"},
        "uapi_version": 5,
    }


def expected_vermagic(profile: dict) -> str:
    return profile.get("module_vermagic", profile["kernel_release"] + " SMP preempt mod_unload aarch64")


def validate_profile(profile: dict) -> None:
    if not isinstance(profile, dict) or not isinstance(profile.get("id"), str) or not ID_PATTERN.fullmatch(profile["id"]):
        raise Error("Invalid profile ID")
    if profile.get("schema", 1) not in {1, 2}:
        raise Error("Unsupported profile schema")
    if profile["id"] != PROFILE_ID and profile.get("schema") != 2:
        raise Error("New profiles must use schema 2")
    if status(profile) not in {"candidate", "verified"}:
        raise Error("Profile validation status must be candidate or verified")
    for field in ("emulator_version", "kernel_release", "kernel_version", "android_version", "ksu_tag"):
        value = profile.get(field)
        if not isinstance(value, str) or not value or any(c in value for c in "\n\r\0'\"`$\\"):
            raise Error(f"Invalid profile field: {field}")
    if profile.get("architecture") != "aarch64":
        raise Error("Only ARM64 MuMu build profiles are implemented")
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", profile["ksu_tag"]):
        raise Error("Invalid build version tag")
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", profile["kernel_release"]):
        raise Error("Invalid kernel release")
    if not isinstance(profile.get("ksu_version"), int) or isinstance(profile["ksu_version"], bool) or profile["ksu_version"] <= 0:
        raise Error("Invalid kernel-side KernelSU version")
    if not matches(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", profile.get("ksu_package")):
        raise Error("Invalid manager package name")
    for name in ("kernel_image_sha256", "config_gz_sha256", "ksud_sha256"):
        if not matches(HEX256, profile.get(name)):
            raise Error(f"Missing SHA-256: {name}")
    if not isinstance(profile.get("sources"), dict) or set(profile["sources"]) != {"kernel", "kernelsu", "userspace", "manager"}:
        raise Error("Profile must pin kernel, KernelSU, userspace and manager sources")
    for name, source in profile["sources"].items():
        if not isinstance(source, dict) or not isinstance(source.get("url"), str) or not source["url"].startswith("https://") or not matches(HEX256, source.get("sha256")):
            raise Error(f"Invalid pinned source: {name}")
    settings = build_settings(profile)
    if settings.get("arch") != "arm64" or settings.get("cross_compile") != "aarch64-linux-gnu-":
        raise Error("Unsupported build toolchain/architecture")
    if not matches(r"[-.A-Za-z0-9_+]*", settings.get("local_version")):
        raise Error("Invalid kernel local version")
    if not matches(r"[A-Za-z0-9_./-]+", settings.get("module_directory")) or ".." in Path(settings["module_directory"]).parts:
        raise Error("Invalid module source directory")
    if Path(settings["module_directory"]).is_absolute():
        raise Error("Module source directory must be relative")
    if not isinstance(settings.get("config"), dict):
        raise Error("Build config must be an object")
    for name, value in settings["config"].items():
        if not matches(r"CONFIG_[A-Z0-9_]+", name) or not isinstance(value, str) or value not in {"y", "m", "n"}:
            raise Error("Build configuration accepts only CONFIG_* = y/m/n")
    if settings.get("config", {}).get("CONFIG_KSU") != "m":
        raise Error("This installer builds a KernelSU loadable module")
    if not isinstance(settings.get("uapi_version"), int) or isinstance(settings["uapi_version"], bool) or settings["uapi_version"] < 1:
        raise Error("Expected KernelSU UAPI version is required")
    repository_file(settings.get("kernel_config"))
    for key in ("kernel_patches", "module_patches"):
        if not isinstance(settings.get(key), list):
            raise Error(f"{key} must be an explicit list")
        for patch in settings[key]:
            repository_file(patch)


def read_profile(profile_id: str) -> dict:
    if not matches(ID_PATTERN, profile_id):
        raise Error("Invalid profile ID")
    path = repository_file(f"profiles/{profile_id}/profile.json")
    profile = json.loads(path.read_text())
    if not isinstance(profile, dict) or profile.get("id") != profile_id:
        raise Error("Profile ID does not match its directory")
    validate_profile(profile)
    return profile


def list_profiles() -> list[dict]:
    result = []
    for path in sorted((ROOT / "profiles").glob("*/profile.json")):
        profile = read_profile(path.parent.name)
        result.append({"id": profile["id"], "status": status(profile), "emulator_version": profile["emulator_version"],
                       "kernel_release": profile["kernel_release"], "ksu_version": profile["ksu_version"]})
    return result
