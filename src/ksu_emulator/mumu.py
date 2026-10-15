from __future__ import annotations

import json
import plistlib
import shlex
import shutil
import time
from pathlib import Path

from .common import Error, run, sha256

DEFAULT_APP = Path("/Applications/MuMuPlayer Pro.app")


class Adb:
    def __init__(self, serial: str, executable: str = "adb"):
        self.serial = serial
        self.executable = executable

    def call(self, *args: str | Path, timeout: int = 30, check: bool = True):
        return run([self.executable, "-s", self.serial, *args], timeout=timeout, check=check)

    def shell(self, command: str, *, timeout: int = 30, check: bool = True) -> str:
        return self.call("shell", command, timeout=timeout, check=check).stdout.decode(errors="replace").strip()

    def bytes(self, command: str) -> bytes:
        return self.call("exec-out", command).stdout

    def push(self, source: Path, dest: str) -> None:
        self.call("push", source, dest, timeout=120)

    def su(self, command: str, *, check: bool = True) -> str:
        return self.shell("su -c " + shlex.quote(command), check=check)


class MuMu:
    def __init__(self, app: Path = DEFAULT_APP, adb: str = "adb"):
        self.app = app.expanduser().resolve()
        self.tool = self.app / "Contents/MacOS/mumutool"
        self.resources = self.app / "Contents/MacOS/MuMu Android Device.app/Contents/Resources/vms.bundle/Contents/Resources"
        self.adb = shutil.which(adb) or str(self.app / "Contents/MacOS/MuMu Android Device.app/Contents/MacOS/tools/adb")
        if not self.tool.is_file():
            raise Error(f"MuMu command-line tool not found: {self.tool}")

    def call(self, command: str, *args: str) -> dict:
        result = run([self.tool, command, *args], timeout=120)
        try:
            value = json.loads(result.stdout)
        except ValueError as exc:
            raise Error("MuMu returned invalid JSON") from exc
        if value.get("errcode") != 0 or "return" not in value:
            raise Error(f"MuMu {command} failed: {value.get('message', value)}")
        return value["return"]

    def instances(self) -> list[dict]:
        return self.call("info", "all")["results"]

    def info(self, index: int) -> dict:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise Error("An explicit nonnegative instance index is required")
        result = self.call("info", str(index))
        if result.get("index") != index:
            raise Error("MuMu returned a different instance")
        return result

    def settings(self, index: int) -> dict:
        path = Path(self.info(index)["bundle_path"]) / "setting/vm.json"
        return json.loads(path.read_text())

    def configure(self, index: int, **settings) -> None:
        self.info(index)
        self.call("config", str(index), "--setting", json.dumps(settings))

    def stop(self, index: int) -> None:
        if self.info(index)["state"] == "stopped":
            return
        self.call("close", str(index))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.info(index)["state"] == "stopped":
                return
            time.sleep(0.5)
        raise Error("Selected MuMu instance did not stop")

    def connect(self, index: int) -> Adb:
        device = self.info(index)
        port = device.get("adb_port")
        if device["state"] != "running" or not isinstance(port, int) or not 1 <= port <= 65535:
            raise Error("Selected MuMu instance is not running with a valid ADB port")
        serial = f"127.0.0.1:{port}"
        run([self.adb, "connect", serial])
        adb = Adb(serial, self.adb)
        if adb.call("get-state").stdout.strip() != b"device":
            raise Error("Selected MuMu ADB device is not ready")
        return adb

    def start(self, index: int, timeout: int = 120) -> Adb:
        state = self.info(index)["state"]
        if state == "stopped":
            self.call("open", str(index))
        deadline = time.monotonic() + timeout
        last = "not ready"
        while time.monotonic() < deadline:
            try:
                adb = self.connect(index)
                if adb.shell("getprop sys.boot_completed", timeout=5) == "1":
                    return adb
            except Error as exc:
                last = str(exc)
            time.sleep(1)
        raise Error(f"MuMu boot timed out: {last}")

    def validate_app(self, profile: dict) -> None:
        with (self.app / "Contents/Info.plist").open("rb") as stream:
            version = plistlib.load(stream)["CFBundleShortVersionString"]
        if version != profile["emulator_version"]:
            raise Error(f"MuMu {version} has no tested install profile; expected {profile['emulator_version']}")
        if sha256(self.resources / "Image") != profile["kernel_image_sha256"]:
            raise Error("MuMu kernel Image differs from the tested profile")
