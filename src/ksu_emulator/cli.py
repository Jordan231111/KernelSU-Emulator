from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .build import build
from .bundle import validate_bundle
from .common import PROFILE_ID, ROOT, Error
from .elf import module_info
from .install import install, verify
from .mumu import DEFAULT_APP, Adb, MuMu
from .probe import probe
from .common import load_profile
from .maintenance import (capture, compare_capture, create_candidate, patch_preflight,
                          read_capture, register_lab)
from .profiles import list_profiles
from .upstream import prepare_framework, updates
from .susfs import build_susfs, validate_susfs, install_susfs, verify_susfs
from .hardening import harden_existing, verify_hardening
from .vendor import clean_vendor_root, verify_vendor_cleanup


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
    deployment = commands.add_parser("install", help="Install into one selected instance, in place")
    deployment.add_argument("--instance", type=int, required=True)
    deployment.add_argument("--bundle", type=Path, default=ROOT / "out" / PROFILE_ID)
    deployment.add_argument("--experimental", action="store_true", help="Permit candidate bundles in registered test instances")
    existing = commands.add_parser("harden-existing", help="Apply verified SELinux hardening to the selected instance")
    existing.add_argument("--instance", type=int, required=True)
    existing.add_argument("--bundle", type=Path, required=True)
    existing.add_argument("--susfs-bundle", type=Path)
    existing.add_argument("--experimental", action="store_true")
    cleanup = commands.add_parser("clean-vendor-root", help="Remove fingerprinted vendor root helpers in place")
    cleanup.add_argument("--instance", type=int, required=True)
    cleanup.add_argument("--profile", default=PROFILE_ID)
    cleanup.add_argument("--experimental", action="store_true")
    cleanup_check = commands.add_parser("verify-vendor-cleanup", help="Check vendor root removal and replacement platform startup")
    cleanup_check.add_argument("--instance", type=int, required=True)
    cleanup_check.add_argument("--profile", default=PROFILE_ID)
    hardening_check = commands.add_parser("verify-hardening", help="Check actual kernel enforcement and the installed repair recipe")
    hardening_check.add_argument("--instance", type=int, required=True)
    hardening_check.add_argument("--profile", default=PROFILE_ID)
    check = commands.add_parser("verify", help="Verify a persistent installation")
    check.add_argument("--instance", type=int, required=True)
    check.add_argument("--root", action="store_true", help="Also test su; Shell must be authorized in Manager")
    check.add_argument("--profile", default=PROFILE_ID)
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
                result = install(mumu, args.instance, args.bundle, experimental=args.experimental)
            elif args.command == "install-susfs":
                result = install_susfs(mumu, args.instance, args.bundle, args.experimental)
            elif args.command == "verify-susfs":
                result = verify_susfs(mumu, args.instance, args.profile)
                if not result["verified"]:
                    print(json.dumps(result, indent=2))
                    return 1
            elif args.command == "harden-existing":
                result = harden_existing(mumu, args.instance, args.bundle, args.susfs_bundle, args.experimental)
            elif args.command == "clean-vendor-root":
                result = clean_vendor_root(mumu, args.instance, args.profile, args.experimental)
            elif args.command == "verify-vendor-cleanup":
                result = verify_vendor_cleanup(mumu, args.instance, args.profile)
                if not result["verified"]:
                    print(json.dumps(result, indent=2))
                    return 1
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
                raise Error("Unknown command")
        print(json.dumps(result, indent=2))
        return 0
    except (Error, OSError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
