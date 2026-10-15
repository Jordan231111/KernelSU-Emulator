from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE_ID = "mumu-pro-1.9.2-arm64"


class Error(RuntimeError):
    pass


def run(args: list[str | Path], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"Cannot run {args[0]}: {exc}") from exc
    if check and result.returncode:
        output = (result.stderr or result.stdout).decode(errors="replace").strip()
        raise Error(f"{args[0]} failed ({result.returncode}): {output[-3000:]}")
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_profile(profile_id: str = PROFILE_ID) -> dict:
    if profile_id != PROFILE_ID:
        raise Error(f"No verified profile for {profile_id}")
    return json.loads((ROOT / "profiles" / profile_id / "profile.json").read_text())


def save_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".ksu-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
