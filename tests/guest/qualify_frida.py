#!/usr/bin/env python3
"""Exercise the existing Frida toolchain in an explicitly selected Android app.

Run with the inventory's Frida Python. The matching server must already be
running. This harness restarts only its selected app, uses its own scratch
files, and leaves that app running after transient instrumentation is removed.
"""
import argparse
import hashlib
import importlib.metadata
import json
import re
import sys
import threading
import time
import uuid
from pathlib import Path

import frida
import frida_tools

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT, save_json
from ksu_emulator.mumu import MuMu


def bounded(function, *args, timeout=60, **kwargs):
    cancel = frida.Cancellable()
    timer = threading.Timer(timeout, cancel.cancel)
    timer.start()
    try:
        with cancel:
            return function(*args, **kwargs)
    finally:
        timer.cancel()


def wait_for(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("Expected event did not arrive")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--native-calls", type=int, default=100000)
    parser.add_argument("--java-calls", type=int, default=10000)
    parser.add_argument("--skip-deopt", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]+", args.package):
        parser.error("Invalid Android package name")
    adb = MuMu().connect(args.instance)
    assert adb.su("cat /sys/fs/selinux/enforce") == "1"
    device = frida.get_device(adb.serial, timeout=5)
    bridge = Path(frida_tools.__file__).parent / "bridges/java.js"
    agent_path = Path(__file__).with_name("frida_agent.js")
    source = bridge.read_text() + "\nglobalThis.Java = bridge;\n" + agent_path.read_text()
    output = ROOT / "out/audit" / ("frida-" + args.package + ".json")
    report = {"instance": args.instance, "package": args.package,
              "client": frida.__version__, "tools": importlib.metadata.version("frida-tools"),
              "bridge_sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
              "agent_sha256": hashlib.sha256(agent_path.read_bytes()).hexdigest(),
              "build_hashes": adb.su("sha256sum /system/etc/ksu-emulator/kernelsu.ko /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko /data/local/tmp/uf-server"),
              "boot_id": adb.su("cat /proc/sys/kernel/random/boot_id"), "cases": {}}
    package_info = adb.shell("dumpsys package " + args.package)
    report["package_version"] = [line.strip() for line in package_info.splitlines()
                                 if re.search(r"\b(versionName|versionCode|minSdk|targetSdk|primaryCpuAbi|userId)=", line)]
    activity = adb.shell("cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER " + args.package).splitlines()[-1]
    assert "/" in activity, activity
    sessions = []
    scripts = []
    messages = []
    detached = []
    cache = None

    def case(name, expected, function):
        print("START", name, flush=True)
        start = time.monotonic()
        message_start = len(messages)
        try:
            observed = function()
            asynchronous_errors = [m["message"] for m in messages[message_start:]
                                   if m["message"].get("type") == "error"]
            if asynchronous_errors:
                raise AssertionError("Asynchronous agent errors: " + json.dumps(asynchronous_errors))
            report["cases"][name] = dict(expected=expected, observed=observed, passed=True)
            print("PASS", name, flush=True)
            return observed
        except Exception as error:
            report["cases"][name] = dict(expected=expected, observed=str(error), passed=False,
                                         exception=type(error).__name__)
            print("FAIL", name, str(error), flush=True)
        finally:
            report["cases"][name]["seconds"] = round(time.monotonic() - start, 3)
            save_json(output, report)

    def check(value, message):
        if not value:
            raise AssertionError(message)
        return value

    def on_message(message, data):
        messages.append({"message": message, "data_hex": data.hex() if data else None})

    def attach(pid):
        session = bounded(device.attach, pid)
        sessions.append(session)
        session.on("detached", lambda reason, crash: detached.append({"reason": reason, "crashed": crash is not None}))
        return session

    def load(session, body, runtime="qjs", binary=False):
        if binary:
            compiled = bounded(session.compile_script, body, runtime=runtime)
            script = bounded(session.create_script_from_bytes, compiled)
        else:
            script = bounded(session.create_script, body, runtime=runtime)
        scripts.append(script)
        script.on("message", on_message)
        bounded(script.load)
        return script

    adb.shell("am force-stop " + args.package)
    adb.shell("am start -W -n " + activity)
    time.sleep(5)
    pid = int(adb.shell("pidof " + args.package).split()[0])
    report["initial_pid"] = pid
    session = attach(pid)
    script = load(session, source)
    rpc = script.exports_sync

    def call(name, *values):
        return bounded(getattr(rpc, name), *values)

    try:
        info = case("discovery_attach", "Matching server/client, app UID, ARM64 Linux, live Java", lambda: call("info"))
        if info is None:
            raise RuntimeError("Agent initialization failed")
        check(info["version"] == frida.__version__ and info["uid"] >= 10000 and info["java"], str(info))
        report["initial_pss_kb"] = adb.su("awk '/^Pss:/ {print $2}' /proc/" + str(pid) + "/smaps_rollup")

        def rpc_test():
            value = {"unicode": "Frida ✓", "nested": [0, 42, None, True]}
            check(call("echo", value) == value and call("delayed", 42) == 42, "RPC roundtrip")
            check(call("binary") == bytes([0, 1, 127, 128, 255]), "binary RPC")
            try:
                call("fail")
                raise AssertionError("Missing RPC exception")
            except frida.core.RPCException as error:
                check("intentional-rpc-test" in str(error), str(error))
            return {"sync": True, "promise": True, "binary": True, "error": True}
        case("rpc", "Structured, asynchronous, binary results and intentional error propagation", rpc_test)

        def message_test():
            call("messaging")
            script.post({"type": "qualification", "value": "qualified"}, bytes([0, 127, 255]))
            value = wait_for(lambda: next((x for x in messages if x["message"].get("payload", {}).get("kind") == "message-reply"), None))
            check(value["data_hex"] == "007fff" and value["message"]["payload"]["value"] == "qualified", str(value))
            return value
        case("messaging", "Host message and binary payload return unchanged", message_test)
        case("native", "CModule, hooks, replacement/revert, callbacks, errno, resolver, symbols, instruction parsing", lambda: call("native", args.native_calls))
        case("memory", "Owned memory scan/read/write/protect, generated ARM64 code, relocation, access monitor, Cloak", lambda: call("memory"))
        java = case("java", "Java hooks and originals, fields, arrays, class registration/enumeration, casts and backtrace", lambda: call("java", args.java_calls))
        if java:
            cache = java["cache"]
            case("java_main_thread", "Scheduled callback runs on Android main thread", lambda: check(call("java_main")["mainThread"], "not main thread"))
            case("java_heap", "Java.choose locates retained diagnostic instance", lambda: check(call("java_choose", java["registered"]) >= 1, "No diagnostic instance"))
            case("files_sqlite_streams", "Own cache file, SQLite and Unix pipe roundtrips", lambda: call("files", cache))
        case("socket", "Loopback listener/connect and byte roundtrip", lambda: call("socket"))
        if args.package == "com.GacoGames.EC2":
            case("unity_il2cpp", "Read-only IL2CPP domain and core-library APIs work in the game", lambda: call("il2cpp"))

        def stalker_test():
            call("start_worker")
            try:
                wait_for(lambda: call("worker_status")["tid"] > 0)
                call("follow_worker")
                call("go_worker")
                wait_for(lambda: call("worker_status")["done"])
                call("unfollow_worker")
                time.sleep(0.5)
            finally:
                result = call("stop_worker")
            check(result["total"] == 1499500 and result["calls"] > 0 and result["blocks"] > 0, str(result))
            return result
        case("stalker", "Owned native worker produces call/block events, completes, detaches and joins", stalker_test)

        def runtimes():
            observed = {}
            for runtime in ("qjs", "v8"):
                simple = load(session, 'rpc.exports = {ping() { return {answer: 42, runtime: Script.runtime}; }};', runtime, binary=runtime == "qjs")
                value = bounded(simple.exports_sync.ping)
                check(value["answer"] == 42 and value["runtime"].lower() == runtime, str(value))
                bounded(simple.unload)
                observed[runtime] = value
            return observed
        case("runtimes_bytecode", "QJS bytecode and V8 source agents load, call and unload", runtimes)

        def injection():
            library = ROOT / "out/guest-tests/native/libfrida_qualification.so"
            remote = "/data/local/tmp/ksu-frida-library-" + uuid.uuid4().hex + ".so"
            uninject = []
            device.on("uninjected", uninject.append)
            values = {}
            try:
                adb.push(library, remote)
                # File injection does not relabel its input; use the existing
                # Frida policy type, never relax shell_data_file execution.
                adb.su("chcon u:object_r:frida_file:s0 " + remote)
                for method in ("file", "blob"):
                    marker = cache + "/ksu-frida-injection-" + uuid.uuid4().hex
                    try:
                        if method == "file":
                            identifier = bounded(device.inject_library_file, pid, remote, "frida_qualification_entry", marker)
                        else:
                            identifier = bounded(device.inject_library_blob, pid, library.read_bytes(), "frida_qualification_entry", marker)
                        wait_for(lambda: identifier in uninject)
                        value = adb.su("cat " + marker)
                        check(value == "frida-injection-qualified", value)
                        values[method] = {"id": identifier, "unloaded": True, "marker": value}
                    finally:
                        adb.su("rm -f " + marker, check=False)
            finally:
                device.off("uninjected", uninject.append)
                # The Frida SELinux label prevents ordinary Shell unlinking.
                adb.su("rm -f " + remote, check=False)
            return values
        if cache:
            case("library_injection", "File and blob injection execute only the diagnostic entrypoint and unload", injection)

        def stress():
            before = call("cleanup")["heap"]
            for i in range(args.cycles):
                another = attach(pid)
                tiny = load(another, 'rpc.exports={roundtrip(v){return {v,pid:Process.id};}};')
                check(bounded(tiny.exports_sync.roundtrip, i) == {"v": i, "pid": pid}, "cycle " + str(i))
                bounded(tiny.unload)
                bounded(another.detach)
            after = call("cleanup")["heap"]
            return {"completed": args.cycles, "heap_before": before, "heap_after": after,
                    "heap_delta": after - before,
                    "pss_kb": adb.su("awk '/^Pss:/ {print $2}' /proc/" + str(pid) + "/smaps_rollup")}
        case("session_stress", "Repeated attach/load/RPC/unload/detach on the same live app", stress)
        if not args.skip_deopt:
            case("java_global_deoptimization", "ART global deoptimization completes", lambda: call("deoptimize"))
        call("cleanup")
        bounded(script.unload)
        bounded(session.detach)

        def reconnect():
            reconnected = attach(pid)
            tiny = load(reconnected, 'rpc.exports={ping(){return Process.id;}};')
            check(bounded(tiny.exports_sync.ping) == pid, "Reconnect PID")
            bounded(tiny.unload); bounded(reconnected.detach)
            return {"pid": pid, "detached_events": len(detached)}
        case("detach_reconnect", "Fresh session works after the full agent and hooks are removed", reconnect)

        def spawn():
            adb.shell("am force-stop " + args.package)
            new_pid = bounded(device.spawn, args.package)
            new_session = attach(new_pid)
            try:
                tiny = load(new_session, 'rpc.exports={ping(){return Process.id;}};')
                check(bounded(tiny.exports_sync.ping) == new_pid, "spawn paused attach")
            finally:
                bounded(device.resume, new_pid)
            time.sleep(5)
            check(int(adb.shell("pidof " + args.package).split()[0]) == new_pid, "spawned process did not survive")
            bounded(tiny.unload); bounded(new_session.detach)
            return {"pid": new_pid, "resumed": True}
        case("spawn_resume", "Spawn, attach before resume, resume and detach leave the app alive", spawn)
        report["completed"] = True
    except Exception as error:
        report["fatal_error"] = str(error)
        raise
    finally:
        for s in reversed(sessions):
            try:
                bounded(s.detach, timeout=5)
            except Exception:
                pass
        report["messages"] = messages
        report["detach_events"] = detached
        # Remove Java classes and deoptimization state created for this run.
        adb.shell("am force-stop " + args.package, check=False)
        adb.shell("am start -W -n " + activity)
        time.sleep(3)
        report["final_pid"] = adb.shell("pidof " + args.package, check=False)
        report["enforcing"] = adb.su("cat /sys/fs/selinux/enforce")
        report["passed"] = report.get("completed", False) and not any(m["message"].get("type") == "error" for m in messages) and bool(report["cases"]) and all(v["passed"] for v in report["cases"].values()) and bool(report["final_pid"]) and report["enforcing"] == "1"
        save_json(output, report)
        print(output, flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
