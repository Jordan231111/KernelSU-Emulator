"""Repair labels on a stopped clone's private ext4 system disk.

MuMu's process-specific file views omit some vendor files. Offline inode access
avoids those views and never edits the application's shared system image.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import struct
import tempfile
import uuid
from pathlib import Path

from .common import ROOT, Error, run, sha256
from .maintenance import require_lab
from .mumu import MuMu


def partition_bounds(header: bytes, image_size: int, partition: int = 1) -> tuple[int, int]:
    if len(header) < 512 or header[510:512] != b"\x55\xaa" or partition not in range(1, 5):
        raise Error("Expected an MBR partition table")
    entry = 446 + (partition - 1) * 16
    start, sectors = struct.unpack_from("<II", header, entry + 8)
    offset, size = start * 512, sectors * 512
    if header[entry + 4] != 0x83 or offset < 512 or size < 2048 or offset + size > image_size:
        raise Error("System partition is not a bounded Linux filesystem partition")
    for i in range(4):
        other = 446 + i * 16
        if i + 1 == partition or header[other + 4] == 0:
            continue
        a, n = struct.unpack_from("<II", header, other + 8)
        if max(offset, a * 512) < min(offset + size, (a + n) * 512):
            raise Error("Partition table contains overlapping partitions")
    return offset, size


def debugfs_rows(output: str) -> list[tuple[int, int, str]]:
    rows = []
    for line in output.splitlines():
        fields = line.split("/")
        if len(fields) >= 7 and fields[1].isdigit():
            name = fields[5]
            if not re.fullmatch(r"[A-Za-z0-9_.@+-]+", name):
                raise Error("Unexpected vendor filename in the offline label repair")
            rows.append((int(fields[1]), int(fields[2], 8), name))
        elif line.startswith("/"):
            raise Error("Malformed vendor directory entry")
    if not rows or not any(name == "." for _, _, name in rows):
        raise Error("Cannot enumerate the required vendor directory")
    return rows


class Ext4Tools:
    def __init__(self):
        self.host = {}
        for name in ("debugfs", "e2fsck"):
            found = shutil.which(name)
            for prefix in ("/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/opt/e2fsprogs/sbin"):
                if not found and (Path(prefix) / name).is_file():
                    found = str(Path(prefix) / name)
            if found:
                self.host[name] = found
        self.docker = len(self.host) != 2
        if self.docker:
            if not shutil.which("docker") or run(["docker", "image", "inspect", "ksu-emulator-toolchain:22.04"], check=False).returncode:
                raise Error("Install e2fsprogs (brew install e2fsprogs), or build this repository's Docker toolchain first")
            run(["docker", "run", "--rm", "ksu-emulator-toolchain:22.04", "sh", "-c",
                 "command -v debugfs >/dev/null && command -v e2fsck >/dev/null"])

    def path(self, path: Path, work: Path) -> str:
        return "/disk/" + str(path.relative_to(work)) if self.docker else str(path)

    def call(self, program: str, args: list, work: Path):
        if not self.docker:
            return run([self.host[program], *args], timeout=180)
        user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
        return run(["docker", "run", "--rm", *user, "-v", f"{work}:/disk",
                    "ksu-emulator-toolchain:22.04", program, *args], timeout=180)


def relabel_system_clone(mumu: MuMu, index: int, trees: list[str], tools: Ext4Tools | None = None) -> dict:
    lab = require_lab(mumu, index)
    if lab.get("source_index") is None:
        raise Error("Offline hardening requires a clone, preserving a complete original instance")
    device = mumu.info(index)
    if device["state"] != "stopped":
        raise Error("Stop the selected clone before its offline disk repair")
    if not trees or any(not re.fullmatch(r"/etc/mumu-configs/[A-Za-z0-9_-]+", p) for p in trees):
        raise Error("Offline labels are limited to explicit MuMu vendor subdirectories")
    disk = Path(device["bundle_path"]).resolve() / "system.qcow2"
    if not disk.is_file() or disk.is_symlink() or disk.stat().st_nlink != 1:
        raise Error("Expected a separate regular private system disk")
    if not shutil.which("qemu-img"):
        raise Error("qemu-img is required")
    ext4 = tools or Ext4Tools()
    before = sha256(disk)
    work_parent = ROOT / ".work/disk-repairs"
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="labels-", dir=work_parent) as temp:
        work = Path(temp)
        raw, part, rebuilt = work / "disk.raw", work / "system.ext4", work / "repaired.qcow2"
        run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw], timeout=600)
        with raw.open("rb") as source:
            offset, size = partition_bounds(source.read(512), raw.stat().st_size)
            source.seek(offset)
            with part.open("wb") as output:
                remaining = size
                while remaining:
                    block = source.read(min(8 << 20, remaining))
                    if not block:
                        raise Error("Truncated system disk")
                    output.write(block)
                    remaining -= len(block)
        with part.open("rb") as source:
            source.seek(1080)
            if source.read(2) != b"\x53\xef":
                raise Error("System partition is not ext4")
        part_arg = ext4.path(part, work)
        ext4.call("e2fsck", ["-fn", part_arg], work)

        def debug(command: str):
            return ext4.call("debugfs", ["-R", command, part_arg], work).stdout.decode(errors="replace")

        pending, entries = list(trees), {}
        while pending:
            directory = pending.pop()
            for inode, mode, name in debugfs_rows(debug(f'ls -p "{directory}"')):
                if name == "..":
                    continue
                path = directory if name == "." else directory + "/" + name
                if stat.S_IFMT(mode) not in {stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK}:
                    raise Error("Unexpected special file in vendor label tree")
                entries[inode] = path
                if name != "." and stat.S_ISDIR(mode):
                    pending.append(path)
                if len(entries) > 2048:
                    raise Error("Vendor label tree exceeds the reviewed size bound")
        context = b"u:object_r:system_file:s0\0"
        value, commands = work / "context.bin", work / "repair.commands"
        value.write_bytes(context)
        value_arg = ext4.path(value, work)
        # Generated inode numbers and a quoted local filename, never guest shell text.
        quoted = '"' + value_arg.replace("\\", "\\\\").replace('"', '\\"') + '"'
        commands.write_text("".join(f"ea_set -f {quoted} <{inode}> security.selinux\n" for inode in entries))
        ext4.call("debugfs", ["-w", "-f", ext4.path(commands, work), part_arg], work)
        verify_commands = work / "verify.commands"
        verification = []
        for inode in entries:
            readback = work / f"readback-{inode}.bin"
            name = ext4.path(readback, work).replace("\\", "\\\\").replace('"', '\\"')
            verification.append(f'ea_get -f "{name}" <{inode}> security.selinux\n')
        verify_commands.write_text("".join(verification))
        ext4.call("debugfs", ["-f", ext4.path(verify_commands, work), part_arg], work)
        for inode in entries:
            readback = work / f"readback-{inode}.bin"
            if not readback.is_file() or readback.read_bytes() != context:
                raise Error(f"Offline label readback failed for {entries[inode]}")
        if part.stat().st_size != size:
            raise Error("Filesystem tool changed the partition size")
        ext4.call("e2fsck", ["-fn", part_arg], work)
        with raw.open("r+b") as target, part.open("rb") as source:
            target.seek(offset)
            shutil.copyfileobj(source, target, 8 << 20)
        run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, rebuilt], timeout=600)
        run(["qemu-img", "check", rebuilt], timeout=180)
        staged = disk.with_name("system.qcow2.labels-" + uuid.uuid4().hex)
        try:
            shutil.copyfile(rebuilt, staged)
            after = sha256(staged)
            if after != sha256(rebuilt):
                raise Error("Repaired disk copy failed checksum verification")
            if mumu.info(index)["state"] != "stopped" or sha256(disk) != before:
                raise Error("The clone changed during the disk repair; the original disk was retained")
            staged.chmod(stat.S_IMODE(disk.stat().st_mode))
            staged.replace(disk)
        finally:
            staged.unlink(missing_ok=True)
    return {"instance": index, "disk_before_sha256": before, "disk_after_sha256": after,
            "labeled_inodes": len(entries), "paths": sorted(entries.values())}
