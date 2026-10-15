#!/usr/bin/env python3
"""Run a validated build plan inside the toolchain container, without shell eval."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    plan = json.loads(Path(sys.argv[1]).read_text())
    settings = plan["build"]
    kernel = Path("/build/kernel")
    extension = plan.get("susfs")
    module = Path("/build/susfs/kernel") if extension else Path("/build/kernelsu") / settings["module_directory"]
    env = dict(os.environ, KBUILD_BUILD_USER="ksu-emulator", KBUILD_BUILD_HOST="reproducible",
               KBUILD_BUILD_TIMESTAMP="2026-10-15 00:00:00 UTC")

    def run(args, cwd=kernel):
        subprocess.run([str(value) for value in args], cwd=cwd, env=env, check=True)

    shutil.copyfile(Path("/src") / settings["kernel_config"], kernel / ".config")
    patches = [(settings["kernel_patches"], kernel)]
    if extension:
        for name in extension["normalize_line_endings"]:
            path = Path("/build/susfs") / name
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
        patches.append((extension["patches"], Path("/build/susfs")))
    else:
        patches.append((settings["module_patches"], Path("/build/kernelsu")))
    for selected, directory in patches:
        for patch in selected:
            run(["patch", "--batch", "--fuzz=0", "-p1", "--input", Path("/src") / patch], cwd=directory)
    run(["scripts/config", "--set-str", "LOCALVERSION", settings["local_version"], "--disable", "LOCALVERSION_AUTO"])
    base = ["make", "ARCH=" + settings["arch"], "CROSS_COMPILE=" + settings["cross_compile"], "HOSTCC=gcc-9"]
    run(base + ["CC=aarch64-linux-gnu-gcc-9", "olddefconfig", "modules_prepare", "-j4"])
    run(base + ["CC=aarch64-linux-gnu-gcc-9", "security/selinux/", "-j4"])
    if extension:
        run(base + ["CC=clang", "M=" + str(module), "KCFLAGS=-g -std=gnu11", "-j4", "modules"])
        shutil.copyfile(module / "susfs_guard_lkm.ko", "/out/susfs_guard_lkm.ko")
        run(["aarch64-linux-gnu-strip", "--strip-debug", "/out/susfs_guard_lkm.ko"])
        run(["clang", "--target=aarch64-linux-gnu", "-O2", "-nostdlib", "-static-pie",
             "-fno-stack-protector", "-fuse-ld=lld", "-Wl,-e,_start",
             "/build/susfs/tools/susfs_sc.c", "-o", "/out/susfs-sc"])
        print("MuMu SUSFS module and freestanding control client built.", flush=True)
        return
    run(base + ["CC=clang", "M=" + str(module)] + [f"{key}={value}" for key, value in settings["config"].items()] + [
        "KSU_VERSION_OVERRIDE=" + str(plan["ksu_version"]), "KSU_VERSION_TAG_OVERRIDE=" + plan["ksu_tag"],
        "KCFLAGS=-g -std=gnu99", "-j4", "modules",
    ])
    shutil.copyfile(module / "kernelsu.ko", "/out/kernelsu.ko")
    run(["aarch64-linux-gnu-strip", "--strip-debug", "/out/kernelsu.ko"])
    run(["aarch64-linux-gnu-gcc-9", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
         "/src/native/ksu_probe.c", "-o", "/out/ksu-probe"])
    print("Module and verification probe built successfully.", flush=True)


if __name__ == "__main__":
    main()
