"""Resolve installed stable Android SDK packages for the diagnostic clients."""
import os
import re
import sys
from pathlib import Path


def sdk_package(kind: str) -> Path:
    root = Path(os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
                or Path.home() / "Library/Android/sdk")
    if kind == "platform":
        directory = root / "platforms"
        override, prefix, required = os.environ.get("ANDROID_PLATFORM"), "android-", "android.jar"
    elif kind == "build-tools":
        directory = root / "build-tools"
        override, prefix, required = os.environ.get("ANDROID_BUILD_TOOLS"), "", "d8"
    elif kind == "ndk":
        explicit = os.environ.get("ANDROID_NDK_ROOT")
        if explicit:
            selected = Path(explicit)
            if (selected / "source.properties").is_file():
                return selected
            raise FileNotFoundError(f"Missing Android NDK at {selected}")
        directory = root / "ndk"
        override, prefix, required = None, "", "source.properties"
    else:
        raise ValueError(f"Unknown SDK package kind: {kind}")
    if override:
        selected = directory / override
        if (selected / required).is_file():
            return selected
        raise FileNotFoundError(f"Missing {selected / required}")
    versions = {}
    for package in directory.glob(prefix + "*"):
        version = package.name.removeprefix(prefix)
        if re.fullmatch(r"\d+(?:\.\d+)*", version) and (package / required).is_file():
            versions[tuple(map(int, version.split(".")))] = package
    if not versions:
        raise FileNotFoundError(f"No installed stable Android {kind} under {directory}")
    return versions[max(versions)]


if __name__ == "__main__":
    print(sdk_package(sys.argv[1]))
