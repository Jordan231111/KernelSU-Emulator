"""Review upstream changes and lock explicitly chosen revisions into candidates."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .build import download
from .common import ROOT, Error, load_profile, save_json, sha256
from .profiles import ID_PATTERN, build_settings, repository_file, validate_profile
from .maintenance import copy_extensions


def framework_settings(profile: dict) -> dict:
    return profile.get("framework", {"name": "KernelSU Next", "repository": "KernelSU-Next/KernelSU-Next", "kernel_ref": "legacy"})


def github(repo: str, suffix: str = "") -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
        raise Error("Invalid GitHub repository")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "KernelSU-Emulator"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(f"https://api.github.com/repos/{repo}{suffix}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise Error(f"GitHub returned HTTP {exc.code} for {repo}{suffix}; check the ref, access and API rate limit") from exc


def updates(profile_id: str) -> dict:
    profile = load_profile(profile_id)
    framework = framework_settings(profile)
    repo = framework["repository"]
    ref = framework["kernel_ref"]
    head = github(repo, "/commits/" + urllib.parse.quote(ref, safe=""))
    release = github(repo, "/releases/latest")
    result = {"profile": profile_id, "repository": repo, "kernel_ref": ref,
            "pinned_kernel_commit": profile["ksu_source_commit"], "upstream_kernel_commit": head["sha"],
            "kernel_changed": head["sha"] != profile["ksu_source_commit"],
            "pinned_manager_tag": profile["ksu_tag"], "latest_manager_tag": release["tag_name"],
            "manager_changed": release["tag_name"] != profile["ksu_tag"],
            "release_url": release["html_url"], "published_at": release.get("published_at"),
            "next_step": "Use prepare-framework with explicit refs, then preflight, build and qualify a fresh lab. No update was installed."}
    extension = ROOT / "profiles" / profile_id / "susfs.json"
    if extension.is_file():
        spec = json.loads(extension.read_text())
        repository = spec.get("repository", "inforcqb/susfs4ksu-lkm")
        source_ref = spec.get("source_ref", "legacy")
        head = github(repository, "/commits/" + urllib.parse.quote(source_ref, safe=""))
        result["susfs"] = {"repository": repository, "source_ref": source_ref,
                           "pinned_commit": spec["source_commit"], "upstream_commit": head["sha"],
                           "changed": head["sha"] != spec["source_commit"],
                           "next_step": "Follow docs/PORTING.md and build the selected SUSFS source for MuMu"}
    return result


def pin_url(url: str, expected_digest: str | None = None) -> dict:
    if not url.startswith("https://"):
        raise Error("Source URLs must use HTTPS")
    cache = ROOT / ".work/cache"
    cache.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="pin-", dir=cache)
    try:
        with os.fdopen(fd, "wb") as output, urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "KernelSU-Emulator"}), timeout=120
        ) as response:
            shutil.copyfileobj(response, output)
        path = Path(name)
        digest = sha256(path)
        if expected_digest and digest != expected_digest.removeprefix("sha256:"):
            raise Error("Upstream release asset digest does not match the downloaded file")
        path.replace(cache / digest)
        return {"url": url, "sha256": digest}
    finally:
        Path(name).unlink(missing_ok=True)


def select_manager(release: dict, asset_name: str | None = None) -> dict:
    assets = [asset for asset in release.get("assets", []) if
              asset["name"] == asset_name] if asset_name else [asset for asset in release.get("assets", []) if
              asset["name"].endswith("-release.apk") and "spoofed" not in asset["name"].lower()]
    if len(assets) != 1:
        raise Error("Select one manager APK with --manager-asset; automatic selection was ambiguous")
    return assets[0]


def prepare_framework(base_id: str, new_id: str, kernel_ref: str, manager_tag: str, asset_name: str | None = None) -> dict:
    if not ID_PATTERN.fullmatch(new_id) or (ROOT / "profiles" / new_id).exists():
        raise Error("Choose a new valid profile ID")
    base = load_profile(base_id)
    framework = framework_settings(base)
    repo = framework["repository"]
    commit = github(repo, "/commits/" + urllib.parse.quote(kernel_ref, safe=""))["sha"]
    release = github(repo, "/releases/tags/" + urllib.parse.quote(manager_tag, safe=""))
    userspace_commit = github(repo, "/commits/" + urllib.parse.quote(release["tag_name"], safe=""))["sha"]
    asset = select_manager(release, asset_name)
    version = re.search(r"_(\d+)-release\.apk$", asset["name"])
    if not version:
        raise Error("Cannot derive the manager version code; this fork needs a manually reviewed profile")
    candidate = copy.deepcopy(base)
    candidate.update({"schema": 2, "id": new_id, "ksu_source_commit": commit,
                      "userspace_source_commit": userspace_commit, "ksu_tag": release["tag_name"],
                      "ksu_version": int(version.group(1)), "build": copy.deepcopy(build_settings(base)),
                      "framework": copy.deepcopy(framework),
                      "validation": {"status": "candidate", "based_on": base_id, "reason": "upstream-update",
                                     "manager_identity_review_required": True}})
    candidate["framework"]["kernel_ref"] = kernel_ref
    for source, url in {
        "kernelsu": f"https://codeload.github.com/{repo}/tar.gz/{commit}",
        "userspace": f"https://codeload.github.com/{repo}/tar.gz/{userspace_commit}",
        "manager": asset["browser_download_url"],
    }.items():
        if url == base["sources"][source]["url"]:
            candidate["sources"][source] = copy.deepcopy(base["sources"][source])
        else:
            candidate["sources"][source] = pin_url(url, asset.get("digest") if source == "manager" else None)
    manager = download(candidate["sources"]["manager"], ROOT / ".work/cache")
    with zipfile.ZipFile(manager) as apk:
        daemon = apk.read("lib/arm64-v8a/libksud.so")
    candidate["ksud_sha256"] = hashlib.sha256(daemon).hexdigest()
    archive = download(candidate["sources"]["kernelsu"], ROOT / ".work/cache")
    with tarfile.open(archive, "r:gz") as source:
        headers = [entry for entry in source.getmembers() if entry.isfile() and entry.name.endswith("/uapi/supercall.h")]
        if len(headers) != 1:
            raise Error("Cannot derive the control API version; review this fork's userspace contract manually")
        content = source.extractfile(headers[0]).read().decode()
        match = re.search(r"#define\s+KERNEL_SU_UAPI_VERSION\s+(\d+)", content)
        if not match:
            raise Error("No recognized KernelSU UAPI version in the selected source")
        candidate["build"]["uapi_version"] = int(match.group(1))
    destination = ROOT / "profiles" / new_id
    destination.mkdir()
    try:
        shutil.copyfile(repository_file(build_settings(base)["kernel_config"]), destination / "kernel.config")
        copy_extensions(base_id, new_id)
        candidate["build"]["kernel_config"] = f"profiles/{new_id}/kernel.config"
        validate_profile(candidate)
        save_json(destination / "profile.json", candidate)
    except Exception:
        shutil.rmtree(destination)
        raise
    return {"profile": new_id, "status": "candidate", "kernel_commit": commit, "manager_tag": manager_tag,
            "uapi_version": candidate["build"]["uapi_version"],
            "next_step": "Review manager identity, run preflight and build, then qualify a fresh labd instance before promotion"}
