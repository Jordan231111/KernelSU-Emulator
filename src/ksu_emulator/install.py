from __future__ import annotations

import json
import shlex
import uuid
from pathlib import Path

from .bundle import SYSTEM_FILES, validate_bundle
from .common import PROFILE_ID, ROOT, Error, load_profile, save_json
from .mumu import Adb, MuMu
from .probe import GUEST_FINGERPRINTS, probe, validate_guest
from .profiles import build_settings, status


def verify(mumu: MuMu, index: int, root: bool = False, profile_id: str = PROFILE_ID) -> dict:
    profile = load_profile(profile_id)
    mumu.validate_app(profile)
    adb = mumu.connect(index)
    evidence = probe(adb, root=root)
    loaded = any(line.startswith("kernelsu ") for line in evidence["kernel_modules"].splitlines())
    evidence["kernel_module_listed"] = loaded
    try:
        evidence["kernel_api"] = json.loads(adb.shell("/system/etc/ksu-emulator/ksu-probe"))
    except (Error, ValueError) as exc:
        evidence["kernel_api_error"] = str(exc)
    api = evidence.get("kernel_api", {})
    api_matches = isinstance(api, dict) and api.get("version") == profile["ksu_version"] and api.get("uapi") == build_settings(profile)["uapi_version"]
    evidence["profile"] = profile_id
    evidence["target_matches_profile"] = all(evidence.get(key) == profile[key] for key in GUEST_FINGERPRINTS)
    # An unapproved Shell cannot get a control descriptor. Preserve verification
    # of a clean installation before its owner grants Shell root. Hidden modules
    # require the real control protocol through an authorized identity.
    kernel_present = api_matches or (loaded and "kernel_api" not in evidence)
    evidence["persistent_install_ready"] = evidence["installer_ready"] == "1" and kernel_present and evidence["target_matches_profile"]
    evidence["privileged_verification_required"] = not loaded and not api_matches
    evidence["disk_cleanup_service"] = adb.shell("getprop init.svc.mumu_disk_cleanup")
    evidence["disk_cleanup_ready"] = evidence["disk_cleanup_service"] == "running"
    if root:
        evidence["root_test"] = adb.su("id; /data/adb/ksud debug version")
        if "uid=0(root)" not in evidence["root_test"] or f"Kernel Version: {profile['ksu_version']}" not in evidence["root_test"]:
            raise Error("KernelSU root verification failed; authorize Shell in KernelSU Manager first")
        evidence["kernel_api"] = json.loads(adb.su("/system/etc/ksu-emulator/ksu-probe"))
        if not isinstance(evidence["kernel_api"], dict) or evidence["kernel_api"].get("version") != profile["ksu_version"] or evidence["kernel_api"].get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("KernelSU control API does not match the selected profile")
        evidence["persistent_install_ready"] = evidence["installer_ready"] == "1" and evidence["target_matches_profile"]
        evidence["privileged_verification_required"] = False
        cleanup_state = adb.su('p=$(pidof mumu-disk-cleanupd); [ -n "$p" ] && '
                              'cat /proc/$p/attr/current && '
                              'grep -E "^(Uid|CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):" /proc/$p/status', check=False)
        # proc attr/current ends with NUL, not necessarily a newline.
        cleanup_state = cleanup_state.replace("\0", "\n")
        evidence["disk_cleanup_process"] = cleanup_state
        required = {"Uid": "1000 1000 1000 1000", "CapEff": "0000000000200000",
                    "CapPrm": "0000000000200000", "CapBnd": "0000000000200000",
                    "NoNewPrivs": "1", "Seccomp": "2"}
        fields = {line.split(":", 1)[0]: " ".join(line.split(":", 1)[1].split())
                  for line in cleanup_state.splitlines() if ":" in line}
        evidence["disk_cleanup_ready"] = (evidence["disk_cleanup_ready"] and
                    "u:r:mumu_disk_cleanup:s0" in cleanup_state and
                    all(fields.get(key) == value for key, value in required.items()))
    evidence["persistent_install_ready"] &= evidence["disk_cleanup_ready"]
    return evidence


def check_existing_install(mumu: MuMu, index: int, adb: Adb, manifest: dict, settings: dict) -> dict | None:
    profile = manifest["profile"]
    package = adb.shell("pm path " + profile["ksu_package"], check=False)
    ready = adb.shell("getprop sys.ksu_emulator.ready") == "1"
    if not package and not ready:
        if adb.shell("if [ -e /system/etc/ksu-emulator ] || [ -e /system/etc/init/ksu-emulator.rc ]; "
                     "then echo installed; fi"):
            raise Error("Existing core files found without a ready installation")
        return None
    if not ready or not package.startswith("package:/") or len(package.splitlines()) != 1:
        raise Error("Existing or incomplete root installation. Check the installed Manager and core before installing")
    if settings.get("vmRootEnable") is not False or settings.get("systemFilePermissionType") != 1:
        raise Error("The installed core requires the private writable disk and disabled MuMu vendor root")
    paths = {name: "/system/etc/ksu-emulator/" + name for name in SYSTEM_FILES}
    paths["ksu-emulator.rc"] = "/system/etc/init/ksu-emulator.rc"
    paths["manager.apk"] = package.removeprefix("package:")
    command = "sha256sum " + " ".join(shlex.quote(path) for path in paths.values())
    # A restricted Shell can see Manager through PackageManager even when it
    # cannot read the installed core. Only request su if the file reads need it.
    observed = adb.call("shell", command, check=False)
    output = observed.stdout.decode(errors="replace") if observed.returncode == 0 else adb.su(command)
    hashes = {parts[1]: parts[0] for line in output.splitlines() if len(parts := line.split(maxsplit=1)) == 2}
    for name, path in paths.items():
        if hashes.get(path) != manifest["files"][name]:
            raise Error("Installed file differs from the selected core bundle: " + name)
    result = verify(mumu, index, profile_id=profile["id"])
    if result["privileged_verification_required"]:
        result = verify(mumu, index, root=True, profile_id=profile["id"])
    if not result["persistent_install_ready"]:
        raise Error("Installed core files match, but runtime verification failed")
    return {**result, "already_installed": True}


def install(mumu: MuMu, index: int, bundle: Path, *, experimental: bool = False) -> dict:
    bundle = bundle.expanduser().resolve()
    manifest = validate_bundle(bundle)
    profile = manifest["profile"]
    if status(profile) != "verified":
        if not experimental:
            raise Error("Candidate bundles require --experimental")
    mumu.validate_app(profile)
    device = mumu.info(index)
    if device["state"] not in {"running", "stopped"}:
        raise Error("Wait for the selected MuMu instance to finish starting/stopping")
    settings = mumu.settings(index)
    mode = settings.get("systemFilePermissionType", 0)
    if mode not in {0, 1}:
        raise Error(f"Untested MuMu system disk mode: {mode}")
    # Boot with the owner's settings first. Repeating an install on a healthy
    # instance must never turn vendor root on or interrupt a running guest.
    existing = check_existing_install(mumu, index, mumu.start(index), manifest, settings)
    if existing is not None:
        return existing
    directory = Path(device["bundle_path"]).resolve()
    record_path = ROOT / "out/installations" / (uuid.uuid4().hex + ".json")
    record = {"schema": 1, "instance": index, "profile": profile["id"], "phase": "preparing"}
    save_json(record_path, record)
    mumu.stop(index)
    stage = None
    try:
        print("Preparing the selected instance's private system disk...", flush=True)
        mumu.configure(index, vmRootEnable=True, systemWritable=True)
        adb = mumu.start(index)
        if not (directory / "system.qcow2").is_file():
            raise Error("MuMu did not create a private system disk")
        evidence = probe(adb)
        validate_guest(evidence, profile)
        record["target_matches_profile"] = True
        if adb.shell("pm path " + profile["ksu_package"], check=False):
            raise Error("KernelSU Next Manager is already installed; use a clean instance")
        conflict = adb.shell(
            "if [ -e /data/adb/ksud ] || [ -e /data/adb/magisk ] || "
            "[ -e /system/etc/ksu-emulator ] || [ -e /system/etc/init/ksu-emulator.rc ]; then echo conflict; fi"
        )
        if conflict or any(line.startswith("kernelsu ") for line in evidence["kernel_modules"].splitlines()):
            raise Error("Existing root framework detected; use a clean instance")
        # Check that MuMu still maps this exact running device before writing.
        if mumu.connect(index).serial != adb.serial:
            raise Error("MuMu changed the selected instance's ADB port during installation")
        stage = "/data/local/tmp/ksu-emulator-" + uuid.uuid4().hex
        adb.shell("mkdir " + shlex.quote(stage))
        for name in sorted(SYSTEM_FILES | {"ksu-emulator.rc"}):
            adb.push(bundle / name, stage + "/" + name)
        staged_files = SYSTEM_FILES | {"ksu-emulator.rc"}
        sums = adb.shell("sha256sum " + " ".join(stage + "/" + name for name in sorted(staged_files)))
        hashes = {parts[1]: parts[0] for line in sums.splitlines() if len(parts := line.split()) == 2}
        if any(hashes.get(stage + "/" + name) != manifest["files"][name] for name in staged_files):
            raise Error("The uploaded core differs from the checked bundle")
        remote = "/system/etc/ksu-emulator"
        command = "set -eu; mkdir " + remote + "; "
        command += "; ".join(f"cp {shlex.quote(stage + '/' + name)} {remote}/{name}" for name in sorted(SYSTEM_FILES))
        command += f"; chmod 0755 {remote}/ksud {remote}/ksu-probe {remote}/boot.sh {remote}/mumu-disk-cleanup {remote}/mumu-disk-cleanupd"
        command += f"; chmod 0644 {remote}/kernelsu.ko {remote}/payload.sha256 {remote}/mumu-disk-cleanup.policy"
        command += f"; cd {remote}; sha256sum -c payload.sha256"
        adb.shell(command)
        adb.call("install", bundle / "manager.apk", timeout=120)
        # Publish the init action last, after the complete payload and APK exist.
        adb.shell(f"set -eu; cp {stage}/ksu-emulator.rc /system/etc/init/ksu-emulator.rc.new; "
                  "chmod 0644 /system/etc/init/ksu-emulator.rc.new; "
                  f"mv /system/etc/init/ksu-emulator.rc.new /system/etc/init/ksu-emulator.rc; rm -rf {stage}; sync")
        record["phase"] = "installed"
        save_json(record_path, record)
        print("Cold booting to verify KernelSU...", flush=True)
        mumu.stop(index)
        adb = mumu.start(index)
        if adb.shell("getprop sys.ksu_emulator.ready") != "1":
            log = adb.shell("cat /data/adb/ksu-emulator/boot.log", check=False)
            raise Error("KernelSU boot hook did not finish:\n" + log[-2500:])
        info = json.loads(adb.shell("/system/etc/ksu-emulator/ksu-probe"))
        if info.get("version") != profile["ksu_version"] or info.get("uapi") != build_settings(profile)["uapi_version"]:
            raise Error("KernelSU control API verification failed")
        record["kernel_api"] = info
        print("Disabling MuMu's vendor root and verifying another cold boot...", flush=True)
        mumu.stop(index)
        mumu.configure(index, vmRootEnable=False)
        adb = mumu.start(index)
        if adb.shell("id -u") != "2000":
            raise Error("MuMu vendor root did not switch off")
        result = verify(mumu, index, profile_id=profile["id"])
        if not result["persistent_install_ready"]:
            raise Error("Persistent KernelSU verification failed")
        record["phase"] = "verified"
        save_json(record_path, record)
        result["record"] = str(record_path)
        return result
    except (Error, OSError, ValueError) as exc:
        if stage:
            try:
                adb.shell("rm -rf " + shlex.quote(stage), check=False)
            except (Error, OSError):
                pass  # Android may already be unreachable; report and stop below.
        record["error"] = str(exc)
        record["phase"] = "failed"
        save_json(record_path, record)
        try:
            mumu.stop(index)
            mumu.configure(index, vmRootEnable=False)
        except (Error, OSError, ValueError) as stop_error:
            raise Error(f"Installation failed: {exc}. Could not stop/disable vendor root: {stop_error}. Record: {record_path}") from exc
        raise Error(f"Installation failed and instance {index} was stopped: {exc}. Record: {record_path}") from exc


def upgrade(mumu: MuMu, index: int, bundle: Path, *, experimental: bool = False) -> dict:
    """Replace a compatible installed core, then qualify its next cold boot."""
    bundle = bundle.expanduser().resolve()
    manifest = validate_bundle(bundle)
    profile = manifest["profile"]
    if status(profile) != "verified" and not experimental:
        raise Error("Candidate bundles require --experimental")
    mumu.validate_app(profile)
    settings = mumu.settings(index)
    if settings.get("vmRootEnable") is not False or settings.get("systemFilePermissionType") != 1:
        raise Error("Core upgrades require the private writable disk and disabled MuMu vendor root")
    adb = mumu.connect(index)
    evidence = probe(adb, root=True)
    if any(evidence.get(key) != profile[key] for key in GUEST_FINGERPRINTS):
        raise Error("The running kernel does not match the upgrade bundle")
    if evidence["installer_ready"] != "1" or adb.su("id -u") != "0":
        raise Error("Core upgrade requires a running installation and authorized Shell root")
    remote = "/system/etc/ksu-emulator"
    adb.su(f"cd {remote} && sha256sum -c payload.sha256")
    hardened = adb.shell("getprop sys.ksu_mumu_policy.enforcing_ready") == "1"
    if hardened:
        from .hardening import wait_hardening
        if not wait_hardening(mumu, index, profile["id"])["verified"]:
            raise Error("Resolve the existing boot health failure before upgrading the core")
    stage = "/data/local/tmp/ksu-upgrade-" + uuid.uuid4().hex
    record_path = ROOT / "out/installations" / (uuid.uuid4().hex + ".json")
    record = {"schema": 1, "instance": index, "profile": profile["id"],
              "kernel_commit": profile["ksu_source_commit"], "files": manifest["files"], "phase": "staging"}
    save_json(record_path, record)
    writable = False
    try:
        adb.shell("mkdir -m 0700 " + stage)
        for name in sorted(SYSTEM_FILES | {"ksu-emulator.rc"}):
            adb.push(bundle / name, stage + "/" + name)
        staged_files = SYSTEM_FILES | {"ksu-emulator.rc"}
        sums = adb.su("sha256sum " + " ".join(stage + "/" + name for name in sorted(staged_files)))
        hashes = {parts[1]: parts[0] for line in sums.splitlines() if len(parts := line.split()) == 2}
        if any(hashes.get(stage + "/" + name) != manifest["files"][name] for name in staged_files):
            raise Error("The uploaded core differs from the checked bundle")
        # PackageManager checks the existing signing identity on replacement.
        adb.call("install", "-r", bundle / "manager.apk", timeout=120)
        if mumu.connect(index).serial != adb.serial:
            raise Error("MuMu changed the selected instance during the upgrade")
        adb.su("mount -o remount,rw /system")
        writable = True
        for name in sorted(SYSTEM_FILES - {"payload.sha256"}) + ["ksu-emulator.rc", "payload.sha256"]:
            dest = "/system/etc/init/" + name if name.endswith(".rc") else remote + "/" + name
            mode = "0755" if name in {"ksud", "ksu-probe", "boot.sh", "mumu-disk-cleanup", "mumu-disk-cleanupd"} else "0644"
            adb.su(f"set -e; cp {stage}/{name} {dest}.new; chown 0:0 {dest}.new; "
                   f"chmod {mode} {dest}.new; chcon u:object_r:system_file:s0 {dest}.new; mv {dest}.new {dest}")
        adb.su(f"cd {remote} && sha256sum -c payload.sha256 && sync")
        # Other mount namespaces can keep this superblock busy. The imminent
        # cold boot closes those references and mounts /system read-only.
        adb.su("mount -o remount,ro /system", check=False)
        record["phase"] = "installed"
        save_json(record_path, record)
        adb.shell("rm -rf " + stage)
        mumu.stop(index)
        writable = False
        adb = mumu.start(index)
        if "ro" not in adb.su("awk '$2 == \"/system\" {print $4}' /proc/mounts").split(","):
            raise Error("The upgraded guest did not mount /system read-only")
        result = check_existing_install(mumu, index, adb, manifest, mumu.settings(index))
        if result is None:
            raise Error("The upgraded core was not found after cold boot")
        if hardened and not wait_hardening(mumu, index, profile["id"])["verified"]:
            raise Error("SELinux service checks failed after the core upgrade")
        record["phase"] = "verified"
        save_json(record_path, record)
        return {**result, "upgraded": True, "kernel_commit": profile["ksu_source_commit"], "record": str(record_path)}
    except (Error, OSError, ValueError) as exc:
        record.update(phase="failed", error=str(exc))
        save_json(record_path, record)
        raise
    finally:
        try:
            if writable:
                adb.su("mount -o remount,ro /system", check=False)
            adb.shell("rm -rf " + stage, check=False)
        except (Error, OSError):
            pass  # Preserve the recorded primary failure if the guest disconnected.
