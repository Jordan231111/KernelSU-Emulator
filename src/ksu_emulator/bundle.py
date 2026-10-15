from __future__ import annotations

import json
from pathlib import Path

from .common import ROOT, Error, load_profile, save_json, sha256
from .elf import module_info

FILES = {"kernelsu.ko", "ksud", "ksu-probe", "manager.apk", "boot.sh", "ksu-emulator.rc", "payload.sha256"}
SYSTEM_FILES = {"kernelsu.ko", "ksud", "ksu-probe", "boot.sh", "payload.sha256"}
RECIPE_FILES = (
    "patches/mumu-task-layout.patch", "patches/kernelsu-next-mumu.patch",
    "scripts/build-in-container.sh", "scripts/Dockerfile", "native/ksu_probe.c",
    "scripts/boot.sh.in", "scripts/ksu-emulator.rc",
    "profiles/mumu-pro-1.9.2-arm64/kernel.config", "profiles/mumu-pro-1.9.2-arm64/profile.json",
)


def recipe_hashes() -> dict:
    return {name: sha256(ROOT / name) for name in RECIPE_FILES}


def finish_bundle(directory: Path, profile: dict) -> dict:
    script = (ROOT / "scripts/boot.sh.in").read_text()
    for key, value in {
        "KERNEL_RELEASE": profile["kernel_release"],
        "KERNEL_VERSION": profile["kernel_version"],
        "CONFIG_SHA256": profile["config_gz_sha256"],
        "KSU_VERSION": profile["ksu_version"],
    }.items():
        script = script.replace(f"@{key}@", str(value))
    (directory / "boot.sh").write_text(script, newline="\n")
    (directory / "ksu-emulator.rc").write_bytes((ROOT / "scripts/ksu-emulator.rc").read_bytes())
    (directory / "payload.sha256").write_text("".join(
        f"{sha256(directory / name)}  {name}\n" for name in sorted(SYSTEM_FILES - {"payload.sha256"})
    ), newline="\n")
    for name in ("ksud", "ksu-probe", "boot.sh"):
        (directory / name).chmod(0o755)
    manifest = {
        "schema": 1,
        "profile": profile,
        "files": {name: sha256(directory / name) for name in sorted(FILES)},
        "recipe": recipe_hashes(),
        "source_archives": {name: sha256(directory / "sources" / name) for name in (
            "kernel.tar.gz", "kernelsu.tar.gz", "userspace.tar.gz", "recipe.tar.gz",
        )},
    }
    save_json(directory / "manifest.json", manifest)
    validate_bundle(directory)
    return manifest


def validate_bundle(directory: Path) -> dict:
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
        profile = manifest["profile"]
        expected = load_profile(profile["id"])
        if manifest["schema"] != 1 or profile != expected:
            raise Error("Bundle profile does not match this repository's tested profile")
        if set(manifest["files"]) != FILES:
            raise Error("Bundle file set is incomplete or contains unexpected paths")
        for name, digest in manifest["files"].items():
            path = directory / name
            if path.is_symlink() or not path.is_file() or sha256(path) != digest:
                raise Error(f"Bundle integrity check failed: {name}")
        if sha256(directory / "manager.apk") != profile["sources"]["manager"]["sha256"]:
            raise Error("Manager APK is not the pinned upstream release")
        if sha256(directory / "ksud") != profile["ksud_sha256"]:
            raise Error("ksud is not the pinned upstream daemon")
        if set(manifest["source_archives"]) != {"kernel.tar.gz", "kernelsu.tar.gz", "userspace.tar.gz", "recipe.tar.gz"}:
            raise Error("Corresponding source archive set is incomplete")
        for name, digest in manifest["source_archives"].items():
            path = directory / "sources" / name
            if path.is_symlink() or not path.is_file() or sha256(path) != digest:
                raise Error(f"Source archive integrity check failed: {name}")
            source = name.removesuffix(".tar.gz")
            if source != "recipe" and digest != profile["sources"][source]["sha256"]:
                raise Error(f"Source archive is not pinned: {name}")
        info = module_info((directory / "kernelsu.ko").read_bytes())
        expected_vermagic = profile["kernel_release"] + " SMP preempt mod_unload aarch64"
        if info["vermagic"].strip() != expected_vermagic:
            raise Error("Kernel module vermagic does not match the profile")
        if info["absolute_symbols"]:
            raise Error("Module is already bound to runtime addresses; supply the unbound build")
        return manifest
    except (KeyError, ValueError, OSError) as exc:
        raise Error(f"Invalid artifact bundle: {exc}") from exc
