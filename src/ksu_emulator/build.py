from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from .bundle import RECIPE_FILES, finish_bundle, recipe_hashes
from .common import ROOT, Error, load_profile, sha256


def download(source: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / source["sha256"]
    if dest.is_file() and sha256(dest) == source["sha256"]:
        return dest
    if not source["url"].startswith("https://"):
        raise Error("Downloads require HTTPS")
    temp = dest.with_suffix(".part")
    try:
        request = urllib.request.Request(source["url"], headers={"User-Agent": "KernelSU-Emulator/0.1"})
        with urllib.request.urlopen(request, timeout=120) as response, temp.open("wb") as output:
            shutil.copyfileobj(response, output)
        if sha256(temp) != source["sha256"]:
            raise Error(f"Checksum mismatch for {source['url']}")
        temp.replace(dest)
    finally:
        temp.unlink(missing_ok=True)
    return dest


def extract_source(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        with tarfile.open(archive, "r:gz") as source:
            # Python's data filter rejects escaping links, devices and traversal.
            source.extractall(temp, filter="data")
        children = list(Path(temp).iterdir())
        if len(children) != 1 or not children[0].is_dir():
            raise Error("Source archive must contain one top-level directory")
        for child in children[0].iterdir():
            shutil.move(str(child), destination / child.name)


def build(output: Path) -> dict:
    profile = load_profile()
    inputs = recipe_hashes()
    output = output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    cache = ROOT / ".work/cache"
    sources = {}
    for key, source in profile["sources"].items():
        print(f"Verifying {key} source/download...", flush=True)
        sources[key] = download(source, cache)
    work_parent = ROOT / ".work/builds"
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mumu-", dir=work_parent) as work:
        work = Path(work)
        extract_source(sources["kernel"], work / "kernel")
        extract_source(sources["kernelsu"], work / "kernelsu")
        print("Building Linux toolchain container...", flush=True)
        result = subprocess.run(["docker", "build", "-t", "ksu-emulator-toolchain:22.04", "-f", str(ROOT / "scripts/Dockerfile"), str(ROOT / "scripts")], check=False)
        if result.returncode:
            raise Error("Toolchain container build failed")
        print("Building the MuMu-specific KernelSU module...", flush=True)
        result = subprocess.run([
            "docker", "run", "--rm", "-v", f"{ROOT}:/src:ro", "-v", f"{work}:/build",
            "-v", f"{output}:/out", "ksu-emulator-toolchain:22.04",
            "bash", "/src/scripts/build-in-container.sh", profile["id"],
        ], check=False)
        if result.returncode:
            raise Error("KernelSU build failed; no verified manifest was produced")
    shutil.copyfile(sources["manager"], output / "manager.apk")
    with zipfile.ZipFile(sources["manager"]) as apk:
        (output / "ksud").write_bytes(apk.read("lib/arm64-v8a/libksud.so"))
    if recipe_hashes() != inputs:
        raise Error("Build inputs changed during compilation; rebuild before publishing a manifest")
    source_dir = output / "sources"
    source_dir.mkdir(exist_ok=True)
    for name in ("kernel", "kernelsu", "userspace"):
        shutil.copyfile(sources[name], source_dir / (name + ".tar.gz"))
    with tarfile.open(source_dir / "recipe.tar.gz", "w:gz") as archive:
        for name in (*RECIPE_FILES, "LICENSE", "NOTICE.md", "README.md", "patches/LICENSE-GPL-2.0", "patches/README.md"):
            archive.add(ROOT / name, arcname=name)
        archive.add(ROOT / "ksu.py", arcname="ksu.py")
        for path in sorted((ROOT / "src").rglob("*.py")):
            archive.add(path, arcname=path.relative_to(ROOT))
    manifest = finish_bundle(output, profile)
    print(f"Verified artifact bundle: {output}", flush=True)
    return manifest
