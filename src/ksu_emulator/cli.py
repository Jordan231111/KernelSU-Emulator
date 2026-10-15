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
from .common import load_profile
from .maintenance import (capture, clone_lab, compare_capture, create_candidate, patch_preflight,
                          read_capture, register_lab)
from .profiles import list_profiles
from .upstream import prepare_framework, updates
from .upgrade import upgrade_clone
from .susfs import build_susfs, validate_susfs, install_susfs, verify_susfs
from .hardening import enhance_clone, verify_hardening


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and install KernelSU Next for verified MuMu kernels.")
    parser.add_argument("--app", type=Path, default=DEFAULT_APP, help="MuMuPlayer Pro.app path")
    parser.add_argument("--adb", default="adb", help="ADB executable")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List MuMu instances")
    commands.add_parser("profiles", help="List verified and candidate compatibility profiles")
    for verb in ("start", "stop"):
        action = commands.add_parser(verb, help=f"{verb.title()} one selected instance")
        action.add_argument("--instance", type=int, required=True)
    create = commands.add_parser("create-lab", help="Create a fresh, isolated MuMu test instance")
    create.add_argument("--name", default="KernelSU Lab")
    clone = commands.add_parser("clone-lab", help="Make a separate test copy, preserving the source")
    clone.add_argument("--instance", type=int, required=True)
    clone.add_argument("--name", default="KernelSU Upgrade Lab")
    snapshot = commands.add_parser("capture", help="Capture kernel identity and compatibility evidence")
    snapshot.add_argument("--instance", type=int, required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    snapshot.add_argument("--root", action="store_true", help="Use already-authorized su for privileged reads")
    comparison = commands.add_parser("compare", help="Compare a capture with a known profile")
    comparison.add_argument("capture", type=Path)
    comparison.add_argument("--profile", default=PROFILE_ID)
    candidate = commands.add_parser("new-profile", help="Prepare a candidate when an app update preserves the kernel ABI")
    candidate.add_argument("--capture", type=Path, required=True)
    candidate.add_argument("--base", default=PROFILE_ID)
    candidate.add_argument("--id", required=True)
    for verb, help_text in (("updates", "Check upstream revisions without installing them"),
                            ("preflight", "Check pinned source patches in a temporary tree")):
        action = commands.add_parser(verb, help=help_text)
        action.add_argument("--profile", default=PROFILE_ID)
    upstream = commands.add_parser("prepare-framework", help="Pin explicitly chosen upstream revisions as a candidate")
    upstream.add_argument("--base", default=PROFILE_ID)
    upstream.add_argument("--id", required=True)
    upstream.add_argument("--kernel-ref", required=True)
    upstream.add_argument("--manager-tag", required=True)
    upstream.add_argument("--manager-asset")
    inspect = commands.add_parser("probe", help="Read kernel capabilities without modifying a guest")
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--instance", type=int)
    target.add_argument("--serial", help="Explicit ADB serial (also supports other emulators)")
    inspect.add_argument("--root", action="store_true", help="Use already-authorized su for protected kernel reads")
    compilation = commands.add_parser("build", help="Build the pinned MuMu module in Docker")
    compilation.add_argument("--output", type=Path)
    compilation.add_argument("--profile", default=PROFILE_ID)
    susfs_build = commands.add_parser("build-susfs", help="Build the pinned MuMu SUSFS KernelSU module ZIP")
    susfs_build.add_argument("--profile", default=PROFILE_ID)
    susfs_build.add_argument("--output", type=Path)
    susfs_check = commands.add_parser("check-susfs-bundle", help="Check SUSFS sources, payload and kernel symbol compatibility")
    susfs_check.add_argument("bundle", type=Path)
    susfs_install = commands.add_parser("install-susfs", help="Install the matched SUSFS ZIP using KernelSU's module installer")
    susfs_install.add_argument("--instance", type=int, required=True)
    susfs_install.add_argument("--bundle", type=Path, required=True)
    susfs_install.add_argument("--experimental", action="store_true")
    susfs_verify = commands.add_parser("verify-susfs", help="Query the real SUSFS API through authorized root")
    susfs_verify.add_argument("--instance", type=int, required=True)
    susfs_verify.add_argument("--profile", default=PROFILE_ID)
    validation = commands.add_parser("check-bundle", help="Verify artifact hashes and module metadata")
    validation.add_argument("bundle", type=Path)
    elf = commands.add_parser("inspect-module", help="Read ARM64 module metadata")
    elf.add_argument("module", type=Path)
    deployment = commands.add_parser("install", help="Install into one selected instance, with backup and rollback")
    deployment.add_argument("--instance", type=int, required=True)
    deployment.add_argument("--bundle", type=Path, default=ROOT / "out" / PROFILE_ID)
    deployment.add_argument("--keep-vendor-root", action="store_true", help="Keep MuMu's original root enabled")
    deployment.add_argument("--experimental", action="store_true", help="Permit candidate bundles in registered test instances")
    upgrade = commands.add_parser("upgrade-clone", help="Upgrade a new clone while retaining the original instance")
    upgrade.add_argument("--instance", type=int, required=True)
    upgrade.add_argument("--from-bundle", type=Path, required=True)
    upgrade.add_argument("--bundle", type=Path, required=True)
    upgrade.add_argument("--name", default="KernelSU Upgraded")
    upgrade.add_argument("--experimental", action="store_true")
    enhancement = commands.add_parser("enhance-clone", help="Create an enforcing clone, optionally with the matching SUSFS module")
    enhancement.add_argument("--instance", type=int, required=True)
    enhancement.add_argument("--from-bundle", type=Path, required=True)
    enhancement.add_argument("--bundle", type=Path, required=True, help="New core bundle (same bundle is allowed)")
    enhancement.add_argument("--susfs-bundle", type=Path)
    enhancement.add_argument("--name", default="KernelSU Next + SUSFS (Enforcing)")
    enhancement.add_argument("--experimental", action="store_true")
    hardening_check = commands.add_parser("verify-hardening", help="Check actual kernel enforcement and the installed repair recipe")
    hardening_check.add_argument("--instance", type=int, required=True)
    hardening_check.add_argument("--profile", default=PROFILE_ID)
    check = commands.add_parser("verify", help="Verify a persistent installation")
    check.add_argument("--instance", type=int, required=True)
    check.add_argument("--root", action="store_true", help="Also test su; Shell must be authorized in Manager")
    check.add_argument("--profile", default=PROFILE_ID)
    recovery = commands.add_parser("restore", help="Restore system disk/settings using an installation receipt")
    recovery.add_argument("receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build(args.output, args.profile)
            result = {"bundle": str((args.output or ROOT / "out" / args.profile).resolve()), "profile": result["profile"]["id"]}
        elif args.command == "profiles":
            result = list_profiles()
        elif args.command == "build-susfs":
            result = build_susfs(args.output, args.profile)
        elif args.command == "check-susfs-bundle":
            manifest = validate_susfs(args.bundle.expanduser().resolve())
            result = {"verified": True, "profile": manifest["profile"]["id"], "status": manifest["specification"]["status"]}
        elif args.command == "compare":
            result = compare_capture(read_capture(args.capture), load_profile(args.profile))
        elif args.command == "new-profile":
            result = create_candidate(args.base, args.capture, args.id)
        elif args.command == "updates":
            result = updates(args.profile)
        elif args.command == "prepare-framework":
            result = prepare_framework(args.base, args.id, args.kernel_ref, args.manager_tag, args.manager_asset)
        elif args.command == "preflight":
            result = patch_preflight(args.profile)
            if not result["passed"]:
                print(json.dumps(result, indent=2))
                return 1
        elif args.command == "check-bundle":
            result = {"verified": True, "profile": validate_bundle(args.bundle)["profile"]["id"]}
        elif args.command == "inspect-module":
            result = module_info(args.module.read_bytes())
        elif args.command == "probe" and args.serial:
            result = probe(Adb(args.serial, args.adb), root=args.root)
        else:
            mumu = MuMu(args.app, args.adb)
            if args.command == "list":
                result = mumu.instances()
            elif args.command == "create-lab":
                result = mumu.call("create", "--setting", json.dumps({
                    "vmName": args.name, "vmCpuCount": 4, "vmMemoryOfMB": 4096,
                    "vmRootEnable": False,
                }))
                result = register_lab(mumu, mumu.info(result["index"]))
            elif args.command == "clone-lab":
                result = clone_lab(mumu, args.instance, args.name)
            elif args.command == "start":
                result = {"instance": args.instance, "serial": mumu.start(args.instance).serial}
            elif args.command == "stop":
                mumu.stop(args.instance)
                result = mumu.info(args.instance)
            elif args.command == "capture":
                result = capture(mumu, args.instance, args.output, args.root)
            elif args.command == "probe":
                result = probe(mumu.connect(args.instance), root=args.root)
            elif args.command == "install":
                result = install(mumu, args.instance, args.bundle, keep_vendor_root=args.keep_vendor_root,
                                 experimental=args.experimental)
            elif args.command == "install-susfs":
                result = install_susfs(mumu, args.instance, args.bundle, args.experimental)
            elif args.command == "verify-susfs":
                result = verify_susfs(mumu, args.instance, args.profile)
                if not result["verified"]:
                    print(json.dumps(result, indent=2))
                    return 1
            elif args.command == "upgrade-clone":
                result = upgrade_clone(mumu, args.instance, args.from_bundle, args.bundle, args.name, args.experimental)
            elif args.command == "enhance-clone":
                result = enhance_clone(mumu, args.instance, args.from_bundle, args.bundle, args.susfs_bundle,
                                       args.name, args.experimental)
            elif args.command == "verify-hardening":
                result = verify_hardening(mumu, args.instance, args.profile)
                if not result["verified"]:
                    print(json.dumps(result, indent=2))
                    return 1
            elif args.command == "verify":
                result = verify(mumu, args.instance, args.root, args.profile)
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
