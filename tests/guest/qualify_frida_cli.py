#!/usr/bin/env python3
"""Bounded live CLI traces and filesystem roundtrips with installed Frida tools."""
import argparse
import hashlib
import json
import os
import pty
import re
import signal
import shutil
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import frida

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT, save_json
from ksu_emulator.mumu import MuMu


class Terminal:
    def __init__(self, command, cwd, log):
        self.data = bytearray()
        self.master, slave = pty.openpty()
        self.process = subprocess.Popen(command, cwd=cwd, stdin=slave, stdout=slave, stderr=slave,
                                        env={**os.environ, "TERM": "xterm-256color"})
        os.close(slave)
        self.log = log
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            while True:
                chunk = os.read(self.master, 65536)
                if not chunk:
                    break
                self.data.extend(chunk)
        except OSError:
            pass

    @property
    def text(self):
        return self.data.decode(errors="replace")

    def wait_text(self, pattern, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if re.search(pattern, self.text):
                return
            if self.process.poll() is not None:
                raise RuntimeError("CLI exited: " + self.text[-1500:])
            time.sleep(0.1)
        raise TimeoutError("CLI readiness: " + self.text[-1500:])

    def close(self):
        forced = False
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            forced = True
            self.process.terminate()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        os.close(self.master)
        self.log.write_bytes(self.data)
        return {"exit": self.process.returncode, "forced_termination": forced, "log": str(self.log)}


def trace_records(path):
    data = path.read_bytes()
    assert data[:4] == b"ITR2"
    offset = 4
    messages = []
    chunks = 0
    chunk_bytes = 0
    while offset < len(data):
        kind, size = struct.unpack_from(">II", data, offset)
        offset += 8
        payload = data[offset:offset + size]
        assert len(payload) == size
        offset += size
        if kind == 1:
            messages.append(json.loads(payload))
            extra, = struct.unpack_from(">I", data, offset)
            offset += 4 + extra
        elif kind == 2:
            chunks += 1
            chunk_bytes += size
        else:
            raise ValueError("Unknown trace record " + str(kind))
    assert offset == len(data)
    return {"bytes": len(data), "chunks": chunks, "chunk_bytes": chunk_bytes,
            "message_types": [m.get("type") for m in messages]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--filesystem", action="store_true")
    args = parser.parse_args()
    assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]+", args.package)
    adb = MuMu().connect(args.instance)
    device = frida.get_device(adb.serial, timeout=5)
    pid = int(adb.shell("pidof " + args.package).split()[0])
    folder = ROOT / "out/audit" / ("frida-live-" + args.package)
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / "results.json"
    report = {"package": args.package, "pid": pid, "client": frida.__version__, "cases": {}}

    def case(name, expected, function):
        print("START", name, flush=True)
        try:
            report["cases"][name] = dict(expected=expected, observed=function(), passed=True)
            print("PASS", name, flush=True)
        except Exception as error:
            report["cases"][name] = dict(expected=expected, observed=str(error), passed=False)
            print("FAIL", name, str(error), flush=True)
        save_json(output, report)

    # Homebrew's Python executable and CLI launchers need not be in the same dir.
    def command(program, *options):
        return [shutil.which(program), "-D", adb.serial, *options]

    def live_trace():
        cmd = command("frida-trace", "-p", str(pid), "-i", "libEGL.so!eglSwapBuffers",
                      "-i", "libvulkan.so!vkQueuePresentKHR", "-j", "android.view.Choreographer!doFrame",
                      "-S", str(ROOT / "scripts/frida-android-init.js"))
        terminal = Terminal(cmd, folder, folder / "function-trace.log")
        try:
            terminal.wait_text(r"\b(?:eglSwapBuffers|vkQueuePresentKHR)\(")
            time.sleep(args.seconds)
            natural = terminal.text
            native = len(re.findall(r"\b(?:eglSwapBuffers|vkQueuePresentKHR)\(", natural))
            java = len(re.findall(r"\bdoFrame\(", natural))
            assert native > 10 and java > 10, {"native": native, "java": java, "tail": natural[-1200:]}
            # Editing an auto-generated handler exercises the CLI's live reload.
            handlers = list((folder / "__handlers__").rglob("eglSwapBuffers.js"))
            if not handlers:
                handlers = list((folder / "__handlers__").rglob("vkQueuePresentKHR.js"))
            assert len(handlers) == 1
            handler = handlers[0]
            original = handler.read_text()
            try:
                updated, count = re.subn(r"(onEnter\([^)]*\)\s*\{)",
                                        r'\1\n    log("qa-hot-reload");', original, count=1)
                assert count == 1, "No native onEnter handler"
                handler.write_text(updated)
                terminal.wait_text(r"qa-hot-reload", timeout=10)
            finally:
                handler.write_text(original)
            return {"native_frame_calls": native, "java_frame_calls": java,
                    "seconds": args.seconds, "live_handler_reload": True}
        finally:
            report["function_trace_stop"] = terminal.close()
    case("live_function_trace", "Natural native and Java frame calls plus live handler reload", live_trace)

    def instruction_trace():
        path = folder / "frame.itrace"
        # A start without an end follows the thread indefinitely. Capture the
        # real caller's return PC so one frame call is a bounded trace.
        session = device.attach(pid)
        locator = session.create_script("""rpc.exports={locate(){return new Promise(resolve=>{
          const start=Process.getModuleByName('libEGL.so').getExportByName('eglSwapBuffers');
          const listener=Interceptor.attach(start,{onEnter(){
            const result={start:start.toString(),end:this.returnAddress.toString(),tid:this.threadId};
            listener.detach();resolve(result);
          }});
        });}};""")
        try:
            locator.load()
            bounds = locator.exports_sync.locate()
        finally:
            locator.unload(); session.detach()
        terminal = Terminal(command("frida-itrace", "-p", str(pid), "-r", bounds["start"] + ".." + bounds["end"],
                                    "-o", str(path)), folder, folder / "instruction-trace.log")
        try:
            terminal.wait_text(r"Tracing|Tracing stopped|Trace finished", timeout=40)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and terminal.process.poll() is None:
                time.sleep(0.1)
        finally:
            report["instruction_trace_stop"] = terminal.close()
        result = trace_records(path)
        result["bounds"] = bounds
        assert result["chunks"] > 0 and result["chunk_bytes"] > 0, result
        assert report["instruction_trace_stop"]["exit"] == 0 and not report["instruction_trace_stop"]["forced_termination"], report["instruction_trace_stop"]
        assert str(pid) in adb.shell("pidof " + args.package, check=False).split(), "Target exited during instruction trace"
        return result
    case("live_instruction_trace", "A bounded real frame call produces instruction chunks and clean trace records", instruction_trace)

    def repl():
        result = subprocess.run(command("frida", "-p", str(pid), "-q", "-e",
            "JSON.stringify({pid:Process.id,arch:Process.arch,java:Java.available})"),
            capture_output=True, text=True, timeout=30)
        assert result.returncode == 0 and '"java":true' in result.stdout, result.stderr + result.stdout
        return result.stdout.strip()
    case("repl", "Existing CLI evaluates Java/native agent expressions in the app", repl)

    if args.filesystem:
        def filesystem():
            local = folder / "transfer.bin"
            local.write_bytes(os.urandom(1048576))
            remote = "/data/local/tmp/ksu-frida-transfer-" + uuid.uuid4().hex
            pulled = folder / "pulled.bin"
            results = {}
            try:
                for program, options in (
                    ("frida-push", (str(local), remote)),
                    ("frida-ls", (remote,)),
                    ("frida-pull", (remote, str(pulled))),
                    ("frida-rm", (remote,)),
                ):
                    process = subprocess.run(command(program, *options), capture_output=True, text=True, timeout=45)
                    results[program] = {"exit": process.returncode, "output": process.stdout[-1000:], "error": process.stderr[-1000:]}
                    assert process.returncode == 0, results[program]
                assert pulled.read_bytes() == local.read_bytes()
                assert not adb.su("test -e " + remote + " && echo exists", check=False)
                return {"sha256": hashlib.sha256(local.read_bytes()).hexdigest(), "bytes": local.stat().st_size, "commands": results}
            finally:
                adb.su("rm -f " + remote, check=False)
                local.unlink(missing_ok=True); pulled.unlink(missing_ok=True)
        case("filesystem_cli", "1 MiB push/list/pull/remove preserves bytes and stat metadata", filesystem)

    report["final_pid"] = adb.shell("pidof " + args.package, check=False)
    report["enforcing"] = adb.su("cat /sys/fs/selinux/enforce")
    report["passed"] = all(v["passed"] for v in report["cases"].values()) and str(pid) in report["final_pid"].split() and report["enforcing"] == "1"
    save_json(output, report)
    print(output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
