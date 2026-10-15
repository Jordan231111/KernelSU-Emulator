from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .build import build
from .bundle import validate_bundle
from .common import PROFILE_ID, ROOT, Error
from .elf import module_info
from .install import install, restore, verify
from .mumu import DEFAULT_APP, Adb, MuMu
from .probe import probe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and install KernelSU Next for verified MuMu kernels.")
    parser.add_argument("--app", type=Path, default=DEFAULT_APP, help="MuMuPlayer Pro.app path")
    parser.add_argument("--adb", default="adb", help="ADB executable")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List MuMu instances")
    create = commands.add_parser("create-lab", help="Create a fresh, isolated MuMu test instance")
    create.add_argument("--name", default="KernelSU Lab")
    inspect = commands.add_parser("probe", help="Read kernel capabilities without modifying a guest")
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--instance", type=int)
    target.add_argument("--serial", help="Explicit ADB serial (also supports other emulators)")
    compilation = commands.add_parser("build", help="Build the pinned MuMu module in Docker")
    compilation.add_argument("--output", type=Path, default=ROOT / "out" / PROFILE_ID)
    validation = commands.add_parser("check-bundle", help="Verify artifact hashes and module metadata")
    validation.add_argument("bundle", type=Path)
    elf = commands.add_parser("inspect-module", help="Read ARM64 module metadata")
    elf.add_argument("module", type=Path)
    deployment = commands.add_parser("install", help="Install into one selected instance, with backup and rollback")
    deployment.add_argument("--instance", type=int, required=True)
    deployment.add_argument("--bundle", type=Path, default=ROOT / "out" / PROFILE_ID)
    deployment.add_argument("--keep-vendor-root", action="store_true", help="Keep MuMu's original root enabled")
    check = commands.add_parser("verify", help="Verify a persistent installation")
    check.add_argument("--instance", type=int, required=True)
    check.add_argument("--root", action="store_true", help="Also test su; Shell must be authorized in Manager")
    recovery = commands.add_parser("restore", help="Restore system disk/settings using an installation receipt")
    recovery.add_argument("receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build(args.output)
            result = {"bundle": str(args.output.resolve()), "profile": result["profile"]["id"]}
        elif args.command == "check-bundle":
            result = {"verified": True, "profile": validate_bundle(args.bundle)["profile"]["id"]}
        elif args.command == "inspect-module":
            result = module_info(args.module.read_bytes())
        elif args.command == "probe" and args.serial:
            result = probe(Adb(args.serial, args.adb))
        else:
            mumu = MuMu(args.app, args.adb)
            if args.command == "list":
                result = mumu.instances()
            elif args.command == "create-lab":
                result = mumu.call("create", "--setting", json.dumps({
                    "vmName": args.name, "vmCpuCount": 4, "vmMemoryOfMB": 4096,
                    "vmRootEnable": False,
                }))
            elif args.command == "probe":
                result = probe(mumu.connect(args.instance))
            elif args.command == "install":
                result = install(mumu, args.instance, args.bundle, keep_vendor_root=args.keep_vendor_root)
            elif args.command == "verify":
                result = verify(mumu, args.instance, args.root)
                if not result["persistent_install_ready"]:
                    print(json.dumps(result, indent=2))
                    return 1
            else:
                result = restore(mumu, args.receipt)
        print(json.dumps(result, indent=2))
        return 0
    except (Error, OSError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
