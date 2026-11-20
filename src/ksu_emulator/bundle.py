from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

from .common import PROFILE_ID, ROOT, Error, load_profile, save_json, sha256
from .elf import module_info, verify_imports
from .profiles import build_settings, expected_vermagic, repository_file

FILES = {"kernelsu.ko", "ksud", "ksu-probe", "manager.apk", "boot.sh", "ksu-emulator.rc", "payload.sha256", "mumu-disk-cleanup", "mumu-disk-cleanupd", "mumu-disk-cleanup.policy"}
SYSTEM_FILES = FILES - {"manager.apk", "ksu-emulator.rc"}
BASE_RECIPE_FILES = (
    "scripts/build-in-container.sh", "scripts/build_module.py", "scripts/Dockerfile", "native/ksu_probe.c",
    "scripts/boot.sh.in", "scripts/ksu-emulator.rc", "native/mumu_disk_cleanup.c", "native/mumu_cleanup_client.c", "scripts/mumu-disk-cleanup.policy",
)


def recipe_files(profile: dict) -> tuple:
    settings = build_settings(profile)
    return tuple(dict.fromkeys((*BASE_RECIPE_FILES, settings["kernel_config"],
        f"profiles/{profile['id']}/profile.json", *settings["kernel_patches"], *settings["module_patches"])))


def recipe_hashes(profile: dict | None = None) -> dict:
    return {name: sha256(ROOT / name) for name in recipe_files(profile or load_profile())}


def render_boot_script(profile: dict) -> str:
    script = (ROOT / "scripts/boot.sh.in").read_text()
    for key, value in {
        "KERNEL_RELEASE": profile["kernel_release"],
        "KERNEL_VERSION": profile["kernel_version"],
        "CONFIG_SHA256": profile["config_gz_sha256"],
        "KSU_VERSION": profile["ksu_version"],
        "KSU_UAPI": build_settings(profile)["uapi_version"],
    }.items():
        script = script.replace(f"@{key}@", str(value))
    return script


def verify_recipe(archive: Path, declared: dict, names: tuple) -> None:
    if not isinstance(declared, dict) or set(declared) != set(names):
        raise Error("Build recipe manifest is incomplete or contains unexpected inputs")
    # Check the recipe that shipped with this build. The host may have since
    # updated its compiler image or CI tools.
    seen = set()
    with tarfile.open(archive, "r:gz") as tar:
        for entry in tar:
            if entry.name not in declared:
                continue
            if entry.name in seen or not entry.isfile():
                raise Error(f"Invalid archived recipe entry: {entry.name}")
            with tar.extractfile(entry) as contents:
                if hashlib.file_digest(contents, "sha256").hexdigest() != declared[entry.name]:
                    raise Error(f"Archived recipe hash differs from the manifest: {entry.name}")
            seen.add(entry.name)
    if seen != set(names):
        raise Error("Corresponding source archive is missing recipe files")


def finish_bundle(directory: Path, profile: dict) -> dict:
    (directory / "boot.sh").write_text(render_boot_script(profile), newline="\n")
    (directory / "ksu-emulator.rc").write_bytes((ROOT / "scripts/ksu-emulator.rc").read_bytes())
    (directory / "mumu-disk-cleanup.policy").write_bytes((ROOT / "scripts/mumu-disk-cleanup.policy").read_bytes())
    (directory / "payload.sha256").write_text("".join(
        f"{sha256(directory / name)}  {name}\n" for name in sorted(SYSTEM_FILES - {"payload.sha256"})
    ), newline="\n")
    for name in ("ksud", "ksu-probe", "boot.sh", "mumu-disk-cleanup", "mumu-disk-cleanupd"):
        (directory / name).chmod(0o755)
    manifest = {
        "schema": 1,
        "profile": profile,
        "files": {name: sha256(directory / name) for name in sorted(FILES)},
        "recipe": recipe_hashes(profile),
        "source_archives": {name: sha256(directory / "sources" / name) for name in (
            "kernel.tar.gz", "kernelsu.tar.gz", "userspace.tar.gz", "recipe.tar.gz",
        )},
    }
    save_json(directory / "manifest.json", manifest)
    try:
        validate_bundle(directory)
    except Exception:
        (directory / "manifest.json").unlink(missing_ok=True)
        raise
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
        files = manifest["files"]
        if files["manager.apk"] != profile["sources"]["manager"]["sha256"]:
            raise Error("Manager APK is not the pinned upstream release")
        if files["ksud"] != profile["ksud_sha256"]:
            raise Error("ksud is not the pinned upstream daemon")
        if (directory / "boot.sh").read_bytes() != render_boot_script(profile).encode() or (
                directory / "ksu-emulator.rc").read_bytes() != (ROOT / "scripts/ksu-emulator.rc").read_bytes():
            raise Error("Core boot scripts differ from the selected install recipe")
        if (directory / "mumu-disk-cleanup.policy").read_bytes() != (ROOT / "scripts/mumu-disk-cleanup.policy").read_bytes():
            raise Error("Disk Cleanup policy differs from the selected install recipe")
        payload = "".join(f"{files[name]}  {name}\n" for name in sorted(SYSTEM_FILES - {"payload.sha256"}))
        if (directory / "payload.sha256").read_bytes() != payload.encode():
            raise Error("Core boot checksums do not cover the bundle payload")
        if set(manifest["source_archives"]) != {"kernel.tar.gz", "kernelsu.tar.gz", "userspace.tar.gz", "recipe.tar.gz"}:
            raise Error("Corresponding source archive set is incomplete")
        for name, digest in manifest["source_archives"].items():
            path = directory / "sources" / name
            if path.is_symlink() or not path.is_file() or sha256(path) != digest:
                raise Error(f"Source archive integrity check failed: {name}")
            source = name.removesuffix(".tar.gz")
            if source != "recipe" and digest != profile["sources"][source]["sha256"]:
                raise Error(f"Source archive is not pinned: {name}")
        verify_recipe(directory / "sources/recipe.tar.gz", manifest["recipe"], recipe_files(profile))
        info = module_info((directory / "kernelsu.ko").read_bytes())
        if info["vermagic"].strip() != expected_vermagic(profile):
            raise Error("Kernel module vermagic does not match the profile")
        if info["absolute_symbols"]:
            raise Error("Module is already bound to runtime addresses; supply the unbound build")
        symbols = f"profiles/{profile['id']}/kernel-symbols.txt"
        if profile["id"] == PROFILE_ID or (ROOT / symbols).is_file():
            verify_imports(info, repository_file(symbols))
        return manifest
    except (KeyError, TypeError, ValueError, OSError, EOFError, tarfile.TarError) as exc:
        raise Error(f"Invalid artifact bundle: {exc}") from exc
