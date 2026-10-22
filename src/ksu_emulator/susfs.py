"""Pinned MuMu SUSFS build, standard KernelSU module packaging and inspection."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import shlex
import uuid
import zipfile
from pathlib import Path

from .build import download, extract_source
from .common import PROFILE_ID, ROOT, Error, load_profile, run, save_json, sha256
from .elf import module_info
from .profiles import HEX256, ID_PATTERN, build_settings, expected_vermagic, matches, repository_file
from .mumu import MuMu

MODULE_FILES = {"module.prop", "customize.sh", "post-fs-data.sh", "boot-completed.sh", "skip_mount",
                "susfs_guard_lkm.ko", "susfs-sc", "payload.sha256"}
RUNTIME_FILES = MODULE_FILES - {"customize.sh", "payload.sha256"}
RECIPE = ("scripts/Dockerfile", "scripts/build_module.py", "scripts/build-in-container.sh",
          "scripts/susfs-post-fs-data.sh.in", "scripts/susfs-customize.sh.in", "scripts/susfs-boot-completed.sh")


def specification(profile_id: str = PROFILE_ID) -> tuple[dict, dict]:
    profile = load_profile(profile_id)
    spec = json.loads(repository_file(f"profiles/{profile_id}/susfs.json").read_text())
    if spec.get("schema") != 1 or spec.get("base_profile") != profile_id or spec.get("status") not in {"candidate", "verified"}:
        raise Error("Invalid SUSFS compatibility specification")
    for key in ("id", "module_id", "module_version", "susfs_version"):
        if not matches(r"[A-Za-z0-9_.-]+", spec.get(key)):
            raise Error(f"Invalid SUSFS field: {key}")
    if not matches(ID_PATTERN, spec["id"]) or not matches(ID_PATTERN, spec["module_id"]):
        raise Error("Invalid SUSFS identifier")
    if not isinstance(spec.get("module_version_code"), int) or isinstance(spec["module_version_code"], bool) or spec["module_version_code"] <= 0:
        raise Error("Invalid SUSFS module version code")
    source = spec.get("source", {})
    if not isinstance(source, dict) or not isinstance(source.get("url"), str) or not source["url"].startswith("https://") or not matches(HEX256, source.get("sha256")):
        raise Error("SUSFS source must be checksum pinned")
    for patch in spec.get("patches", []):
        repository_file(patch)
    if not spec.get("patches") or not isinstance(spec.get("normalize_line_endings"), list):
        raise Error("SUSFS patch/normalization recipe is missing")
    for name in spec["normalize_line_endings"]:
        if not matches(r"kernel/[A-Za-z0-9_.-]+\.[ch]", name):
            raise Error("Invalid source normalization path")
    repository_file(spec.get("kernel_symbols"))
    return profile, spec


def recipe_files(profile: dict, spec: dict) -> tuple:
    settings = build_settings(profile)
    return tuple(dict.fromkeys((*RECIPE, settings["kernel_config"],
        f"profiles/{profile['id']}/profile.json", f"profiles/{profile['id']}/susfs.json",
        spec["kernel_symbols"], *settings["kernel_patches"], *spec["patches"])))


def template(name: str, profile: dict, spec: dict) -> str:
    content = repository_file(name).read_text()
    for key, value in {"KERNEL_RELEASE": profile["kernel_release"], "KERNEL_VERSION": profile["kernel_version"],
                       "CONFIG_SHA256": profile["config_gz_sha256"], "VENDOR_SHA256": profile["vendor_module_sha256"],
                       "SUSFS_VERSION": spec["susfs_version"]}.items():
        content = content.replace("@" + key + "@", value)
    return content


def build_susfs(output: Path | None = None, profile_id: str = PROFILE_ID) -> dict:
    profile, spec = specification(profile_id)
    output = (output or ROOT / "out" / spec["id"]).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").unlink(missing_ok=True)
    inputs = {name: sha256(ROOT / name) for name in recipe_files(profile, spec)}
    print(f"Building {spec['id']} ({spec['status']})", flush=True)
    kernel = download(profile["sources"]["kernel"], ROOT / ".work/cache")
    source = download(spec["source"], ROOT / ".work/cache")
    parent = ROOT / ".work/builds"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="susfs-", dir=parent) as tmp:
        work = Path(tmp)
        extract_source(kernel, work / "kernel")
        extract_source(source, work / "susfs")
        save_json(work / "build-plan.json", {"build": build_settings(profile), "susfs": spec})
        command = ["docker", "build", "-t", "ksu-emulator-toolchain:22.04", "-f", str(ROOT / "scripts/Dockerfile"), str(ROOT / "scripts")]
        if subprocess.run(command, check=False).returncode:
            raise Error("SUSFS build toolchain failed")
        user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
        command = ["docker", "run", "--rm", *user, "-v", f"{ROOT}:/src:ro", "-v", f"{work}:/build",
                   "-v", f"{output}:/out", "ksu-emulator-toolchain:22.04", "bash",
                   "/src/scripts/build-in-container.sh", "/build/build-plan.json"]
        if subprocess.run(command, check=False).returncode:
            raise Error("SUSFS compilation failed")
    if inputs != {name: sha256(ROOT / name) for name in inputs}:
        raise Error("SUSFS build recipe changed during compilation")
    module = output / "module"
    module.mkdir(exist_ok=True)
    for name in ("susfs_guard_lkm.ko", "susfs-sc"):
        shutil.copyfile(output / name, module / name)
    (module / "module.prop").write_text(
        f"id={spec['module_id']}\nname=MuMu SUSFS\nversion={spec['module_version']} ({spec['susfs_version']})\n"
        f"versionCode={spec['module_version_code']}\nauthor=KernelSU-Emulator contributors\n"
        "description=Version-locked SUSFS LKM port for MuMu Pro on Apple Silicon. Reboot required for removal.\n")
    (module / "skip_mount").write_bytes(b"")
    (module / "customize.sh").write_text(template("scripts/susfs-customize.sh.in", profile, spec), newline="\n")
    (module / "post-fs-data.sh").write_text(template("scripts/susfs-post-fs-data.sh.in", profile, spec), newline="\n")
    (module / "boot-completed.sh").write_bytes(repository_file("scripts/susfs-boot-completed.sh").read_bytes())
    for name in ("post-fs-data.sh", "boot-completed.sh", "susfs-sc"):
        (module / name).chmod(0o755)
    # KernelSU deliberately removes customize.sh after installation.
    (module / "payload.sha256").write_text("".join(f"{sha256(module / name)}  {name}\n" for name in sorted(RUNTIME_FILES)), newline="\n")
    archive = output / (spec["id"] + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        for name in sorted(MODULE_FILES):
            zipped.write(module / name, name)
    sources = output / "sources"
    sources.mkdir(exist_ok=True)
    shutil.copyfile(kernel, sources / "kernel.tar.gz")
    shutil.copyfile(source, sources / "susfs.tar.gz")
    with tarfile.open(sources / "recipe.tar.gz", "w:gz") as tar:
        for name in (*recipe_files(profile, spec), "LICENSE", "NOTICE.md", "patches/LICENSE-GPL-2.0", "ksu.py"):
            tar.add(ROOT / name, arcname=name)
        for path in sorted((ROOT / "src").rglob("*.py")):
            tar.add(path, arcname=path.relative_to(ROOT))
    manifest = {"schema": 1, "kind": "mumu-susfs", "profile": profile, "specification": spec,
                "archive": archive.name, "archive_sha256": sha256(archive), "recipe": inputs,
                "files": {name: sha256(module / name) for name in sorted(MODULE_FILES)},
                "sources": {name: sha256(sources / name) for name in ("kernel.tar.gz", "susfs.tar.gz", "recipe.tar.gz")}}
    save_json(output / "manifest.json", manifest)
    validate_susfs(output)
    print(f"Verified bundle: {output}", flush=True)
    return {"bundle": str(output), "module_zip": str(archive), "status": spec["status"]}


def validate_susfs(directory: Path) -> dict:
    try:
        value = json.loads((directory / "manifest.json").read_text())
        profile, spec = specification(value["profile"]["id"])
        if value.get("schema") != 1 or value.get("kind") != "mumu-susfs" or value["profile"] != profile or value["specification"] != spec:
            raise Error("SUSFS bundle differs from its pinned compatibility specification")
        archive = directory / (spec["id"] + ".zip")
        if value["archive"] != archive.name or archive.is_symlink() or sha256(archive) != value["archive_sha256"]:
            raise Error("SUSFS ZIP integrity check failed")
        if set(value["files"]) != MODULE_FILES:
            raise Error("Unexpected SUSFS payload file set")
        with zipfile.ZipFile(archive) as zipped:
            if len(zipped.namelist()) != len(MODULE_FILES) or set(zipped.namelist()) != MODULE_FILES:
                raise Error("Unsafe or incomplete SUSFS ZIP")
            import hashlib
            for name in MODULE_FILES:
                if hashlib.sha256(zipped.read(name)).hexdigest() != value["files"][name]:
                    raise Error(f"SUSFS payload changed: {name}")
            info = module_info(zipped.read("susfs_guard_lkm.ko"), expected_name="susfs_guard_lkm")
        if info["absolute_symbols"] or info["vermagic"].strip() != expected_vermagic(profile):
            raise Error("SUSFS module is bound to runtime addresses or has the wrong kernel ABI")
        symbols = set(repository_file(spec["kernel_symbols"]).read_text().splitlines())
        missing = sorted(set(info["undefined_symbols"]) - symbols)
        if missing:
            raise Error("SUSFS imports symbols absent from the measured kernel: " + ", ".join(missing))
        if set(value["sources"]) != {"kernel.tar.gz", "susfs.tar.gz", "recipe.tar.gz"}:
            raise Error("SUSFS corresponding source archives are incomplete")
        for name, digest in value["sources"].items():
            source = directory / "sources" / name
            if source.is_symlink() or sha256(source) != digest:
                raise Error(f"SUSFS source archive changed: {name}")
        if value["sources"]["kernel.tar.gz"] != profile["sources"]["kernel"]["sha256"] or value["sources"]["susfs.tar.gz"] != spec["source"]["sha256"]:
            raise Error("SUSFS source archives are not the pinned upstream inputs")
        return value
    except (KeyError, OSError, ValueError, zipfile.BadZipFile) as exc:
        raise Error(f"Invalid SUSFS bundle: {exc}") from exc


def verify_susfs(mumu: MuMu, index: int, profile_id: str = PROFILE_ID) -> dict:
    profile, spec = specification(profile_id)
    mumu.validate_app(profile)
    adb = mumu.connect(index)
    version = adb.su("/data/adb/ksud susfs version")
    variant = adb.su("/data/adb/ksud susfs variant")
    features = adb.su("/data/adb/ksud susfs features").splitlines()
    counters = adb.su("cat /sys/module/susfs_guard_lkm/parameters/legacy_path_stats")
    ready = adb.shell("getprop sys.ksu_mumu.susfs_ready") == "1"
    return {"instance": index, "version": version, "variant": variant, "declared_features": features,
            "boot_configuration_ready": ready, "path_counters": counters,
            "verified": ready and version == spec["susfs_version"] and variant == "NON-GKI",
            "note": "Engine/API/startup verification; behavioral checks are described in tests/guest/README.md"}


def install_susfs(mumu: MuMu, index: int, bundle: Path, experimental: bool = False) -> dict:
    bundle = bundle.expanduser().resolve()
    manifest = validate_susfs(bundle)
    profile, spec = manifest["profile"], manifest["specification"]
    if spec["status"] != "verified":
        if not experimental:
            raise Error("Candidate SUSFS bundles require --experimental and a registered test instance")
        from .maintenance import require_lab
        require_lab(mumu, index)
    from .install import verify
    if not verify(mumu, index, root=True, profile_id=profile["id"])["persistent_install_ready"]:
        raise Error("A verified KernelSU-Emulator base and authorized Shell are required")
    adb = mumu.connect(index)
    was_hardened = adb.shell("getprop sys.ksu_mumu_policy.enforcing_ready") == "1" and adb.su("cat /sys/fs/selinux/enforce") == "1"
    if adb.shell("getprop sys.ksu_mumu_policy.fallback"):
        raise Error("Resolve the SELinux hardening fallback state before adding another kernel component")
    stage = "/data/local/tmp/mumu-susfs-" + uuid.uuid4().hex + ".zip"
    adb.push(bundle / manifest["archive"], stage)
    try:
        print(adb.su("/data/adb/ksud module install " + shlex.quote(stage)), flush=True)
        adb.shell("rm -f " + shlex.quote(stage))
        adb.su(f"rm -f /data/adb/modules/{spec['module_id']}/disable /data/adb/modules_update/{spec['module_id']}/disable")
        mumu.stop(index)
        mumu.start(index)
        if was_hardened:
            from .hardening import wait_hardening
            if not wait_hardening(mumu, index, profile["id"])["verified"]:
                raise Error("SELinux service checks failed after SUSFS installation")
        result = verify_susfs(mumu, index, profile["id"])
        if not result["verified"]:
            raise Error("SUSFS startup did not complete")
        return result
    except (Error, OSError, ValueError) as exc:
        try:
            adb.shell("rm -f " + shlex.quote(stage), check=False)
        except (Error, OSError):
            pass
        # Its own pending-boot guard prevents a failed boot from loading it again.
        # Also request the standard module disable path when ADB is available.
        try:
            adb = mumu.start(index)
            adb.su("touch /data/adb/modules/" + spec["module_id"] + "/disable")
            if was_hardened:
                adb.su("rm -f /data/adb/ksu-emulator/enforcing-pending")
            mumu.stop(index)
            mumu.start(index)
        except (Error, OSError) as disable_error:
            raise Error(f"SUSFS installation failed: {exc}. Could not disable the module: {disable_error}. Disable {spec['module_id']} in Manager.") from exc
        raise Error(f"SUSFS installation failed: {exc}. The module was disabled and the instance cold-booted.") from exc
