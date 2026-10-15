"""Read-only captures, explicit candidate profiles and patch preflight."""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
import plistlib
import re
import shlex
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .build import download, extract_source
from .common import PROFILE_ID, ROOT, Error, load_profile, run, save_json, sha256
from .elf import module_info
from .mumu import MuMu
from .probe import probe
from .profiles import ID_PATTERN, build_settings, repository_file, status, validate_profile

KERNEL_FIELDS = ("kernel_image_sha256", "kernel_release", "kernel_version", "architecture", "config_gz_sha256")


def capture(mumu: MuMu, index: int, output: Path, root: bool = False) -> dict:
    output = output.expanduser().resolve()
    if output.exists():
        raise Error("Capture output already exists; use a new directory")
    info = mumu.info(index)
    adb = mumu.connect(index)
    evidence = probe(adb, root=root)
    read_text = adb.su if root else adb.shell
    boot_id = read_text("cat /proc/sys/kernel/random/boot_id")
    with (mumu.app / "Contents/Info.plist").open("rb") as stream:
        app_version = plistlib.load(stream)["CFBundleShortVersionString"]
    config = adb.bytes("su -c 'cat /proc/config.gz'" if root else "cat /proc/config.gz")
    if hashlib.sha256(config).hexdigest() != evidence.get("config_gz_sha256"):
        raise Error("Kernel configuration changed during capture")
    output.mkdir(parents=True, mode=0o700)
    (output / "config.gz").write_bytes(config)
    (output / "kernel.config").write_bytes(gzip.decompress(config))
    evidence.update({"emulator_version": app_version, "kernel_image_sha256": sha256(mumu.resources / "Image"),
                     "initrd_sha256": sha256(mumu.resources / "initrd.img")})
    errors = {}
    reference = f"/system/lib/modules/{evidence['kernel_release']}/extra/vaddress.ko"
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", evidence["kernel_release"]):
        raise Error("Unexpected kernel release syntax")

    def read(command):
        return adb.bytes("su -c " + shlex.quote(command) if root else command)

    try:
        binary = read("cat " + shlex.quote(reference))
        metadata = module_info(binary, expected_name=None)
        (output / "reference-module.ko").write_bytes(binary)
        evidence["vendor_module_sha256"] = hashlib.sha256(binary).hexdigest()
        evidence["module_vermagic"] = metadata["vermagic"].strip()
        save_json(output / "reference-module.json", metadata)
    except Error as exc:
        errors["reference_module"] = str(exc)
    try:
        symbols = read("cat /proc/kallsyms").decode()
        # Names/types are sufficient for symbol preflight. Do not save runtime addresses.
        rows = [" ".join(line.split()[1:3]) for line in symbols.splitlines() if len(line.split()) == 3]
        if not rows:
            raise Error("Kernel symbol names are unavailable")
        (output / "symbols.txt").write_text("\n".join(rows) + "\n", newline="\n")
    except Error as exc:
        errors["symbols"] = str(exc)
    try:
        evidence["selinux_observation"] = read("cat /sys/fs/selinux/enforce").decode().strip()
        evidence["selinux_privileged_read"] = root
    except Error as exc:
        errors["selinux"] = str(exc)
    now = mumu.info(index)
    if now.get("pid") != info.get("pid") or now.get("adb_port") != info.get("adb_port") or read_text("cat /proc/sys/kernel/random/boot_id") != boot_id:
        raise Error("The instance changed during capture; discard this incomplete snapshot")
    report = {"schema": 1, "captured_at_utc": datetime.now(timezone.utc).isoformat(), "instance": index,
              "evidence": evidence, "errors": errors,
              "files": {p.name: sha256(p) for p in output.iterdir() if p.is_file()}}
    save_json(output / "report.json", report)
    return report


def read_capture(path: Path) -> dict:
    path = path.expanduser().resolve()
    if path.is_dir():
        path /= "report.json"
    report = json.loads(path.read_text())
    if report.get("schema") != 1 or not isinstance(report.get("evidence"), dict):
        raise Error("Invalid capture report")
    if not isinstance(report.get("files"), dict):
        raise Error("Invalid capture file manifest")
    for name, digest in report["files"].items():
        if Path(name).name != name or name in {".", ".."} or (path.parent / name).is_symlink() or sha256(path.parent / name) != digest:
            raise Error(f"Capture file integrity check failed: {name}")
    if not {"config.gz", "kernel.config"} <= set(report.get("files", {})):
        raise Error("Capture lacks a verified kernel configuration")
    return report


def compare_capture(report: dict, profile: dict) -> dict:
    evidence = report["evidence"]
    fields = (*KERNEL_FIELDS, "vendor_module_sha256", "emulator_version", "android_version")
    changes = {key: {"before": profile.get(key), "after": evidence.get(key)}
               for key in fields if profile.get(key) != evidence.get(key)}
    kernel_changed = any(key in changes for key in KERNEL_FIELDS)
    missing_reference = not evidence.get("vendor_module_sha256")
    driver_changed = "vendor_module_sha256" in changes
    classification = ("kernel-port-required" if kernel_changed or driver_changed else
                      "app-update-same-kernel" if changes else "identical-tested-target")
    if missing_reference:
        classification = "insufficient-evidence"
    return {"profile": profile["id"], "classification": classification, "changes": changes,
            "reuse_build_candidate": not missing_reference and not kernel_changed and not driver_changed,
            "required_next_step": "Measure ABI and audit symbols before building" if kernel_changed or driver_changed else
            "Qualify a clone before promoting a new app version; matching kernel files do not prove boot compatibility"}


def create_candidate(base_id: str, capture_path: Path, new_id: str) -> dict:
    if not ID_PATTERN.fullmatch(new_id) or new_id == PROFILE_ID:
        raise Error("Choose a new valid candidate profile ID")
    base = load_profile(base_id)
    report = read_capture(capture_path)
    comparison = compare_capture(report, base)
    # New kernel ABIs need deliberate source/config/patch selection, not guessed padding.
    if not comparison["reuse_build_candidate"]:
        raise Error("Kernel or vendor ABI changed. Use the kernel-port workflow in docs/UPDATING.md; automatic reuse is refused")
    candidate = copy.deepcopy(base)
    candidate.update({"schema": 2, "id": new_id, "build": copy.deepcopy(build_settings(base)),
                      "validation": {"status": "candidate", "based_on": base_id, "reason": comparison["classification"]}})
    for key in (*KERNEL_FIELDS, "emulator_version", "android_version", "vendor_module_sha256", "module_vermagic"):
        if key in report["evidence"]:
            candidate[key] = report["evidence"][key]
    candidate["build"]["kernel_config"] = f"profiles/{new_id}/kernel.config"
    candidate["framework"] = copy.deepcopy(base.get("framework", {"name": "KernelSU Next", "repository": "KernelSU-Next/KernelSU-Next", "kernel_ref": "legacy"}))
    destination = ROOT / "profiles" / new_id
    if destination.exists():
        raise Error("Candidate profile already exists")
    source = capture_path.expanduser().resolve()
    source = source if source.is_dir() else source.parent
    destination.mkdir()
    try:
        shutil.copyfile(source / "kernel.config", destination / "kernel.config")
        copy_extensions(base_id, new_id)
        validate_profile(candidate)
        save_json(destination / "profile.json", candidate)
    except Exception:
        shutil.rmtree(destination)
        raise
    return {"profile": new_id, "status": "candidate", "path": str(destination), "comparison": comparison}


def copy_extensions(base_id: str, new_id: str) -> None:
    """Carry optional recipes forward as candidates, never as new validation."""
    source = ROOT / "profiles" / base_id
    destination = ROOT / "profiles" / new_id
    old_prefix, new_prefix = f"profiles/{base_id}/", f"profiles/{new_id}/"

    def rewrite(value):
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, str) and value.startswith(old_prefix):
            return new_prefix + value[len(old_prefix):]
        return value

    for name in ("hardening", "kernel-symbols.txt"):
        path = source / name
        if path.is_dir():
            shutil.copytree(path, destination / name)
        elif path.is_file():
            shutil.copyfile(path, destination / name)
    for name in ("hardening", "susfs"):
        path = source / (name + ".json")
        if not path.is_file():
            continue
        spec = rewrite(json.loads(path.read_text()))
        spec.update(base_profile=new_id, status="candidate", id=new_id + "-" + name)
        save_json(destination / path.name, spec)


def patch_preflight(profile_id: str) -> dict:
    profile = load_profile(profile_id)
    settings = build_settings(profile)
    results = []
    with tempfile.TemporaryDirectory(prefix="ksu-preflight-") as temp:
        work = Path(temp)
        for name, key in (("kernel", "kernel_patches"), ("kernelsu", "module_patches")):
            archive = download(profile["sources"][name], ROOT / ".work/cache")
            destination = work / name
            extract_source(archive, destination)
            for patch in settings[key]:
                args = ["patch", "--batch", "--fuzz=0", "-p1", "-d", destination, "--input", repository_file(patch)]
                result = run([*args, "--dry-run"], check=False)
                passed = result.returncode == 0
                results.append({"patch": patch, "applies": passed, "output": result.stdout.decode(errors="replace").strip()})
                if not passed:
                    return {"profile": profile_id, "passed": False, "patches": results}
                run(args)  # Later patches may depend on earlier ones; only the temporary tree changes.
    return {"profile": profile_id, "status": status(profile), "passed": True, "patches": results,
            "note": "Clean patch application is not a kernel ABI or runtime compatibility guarantee"}


def register_lab(mumu: MuMu, device: dict, source_index: int | None = None) -> dict:
    record = {"index": device["index"], "bundle_path": str(Path(device["bundle_path"]).resolve()), "source_index": source_index}
    save_json(ROOT / "out/labs" / f"{device['index']}.json", record)
    return device


def require_lab(mumu: MuMu, index: int) -> dict:
    path = ROOT / "out/labs" / f"{index}.json"
    if not path.is_file():
        raise Error("Candidate testing requires an instance made by create-lab or clone-lab")
    record = json.loads(path.read_text())
    if record.get("index") != index or record.get("bundle_path") != str(Path(mumu.info(index)["bundle_path"]).resolve()):
        raise Error("Laboratory instance identity changed")
    return record


def clone_lab(mumu: MuMu, index: int, name: str) -> dict:
    before = mumu.info(index)
    if before["state"] not in {"running", "stopped"}:
        raise Error("Source instance is busy")
    mumu.stop(index)
    try:
        result = mumu.call("clone", str(index))
        # Keep the clone discoverable even if a later rename fails.
        register_lab(mumu, result, index)
        mumu.configure(result["index"], vmName=name)
        result["name"] = name
        return result
    finally:
        if before["state"] == "running":
            mumu.start(index)
