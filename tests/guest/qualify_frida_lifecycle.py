#!/usr/bin/env python3
"""Repeatedly unload live Java frame hooks while the chosen game keeps rendering."""
import argparse
import json
import sys
import time
from pathlib import Path

import frida
import frida_tools

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ksu_emulator.common import ROOT, save_json
from ksu_emulator.mumu import MuMu
from qualify_frida import bounded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", type=int, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--cycles", type=int, default=30)
    parser.add_argument("--deopt", choices=("all", "none"), default="all")
    args = parser.parse_args()
    adb = MuMu().connect(args.instance)
    activity = adb.shell("cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER " + args.package).splitlines()[-1]
    adb.shell("am force-stop " + args.package)
    adb.shell("am start -W -n " + activity)
    time.sleep(3)
    pid = int(adb.shell("pidof " + args.package).split()[0])
    device = frida.get_device(adb.serial, timeout=5)
    bridge = Path(frida_tools.__file__).parent / "bridges/java.js"
    if args.deopt == "all":
        session = bounded(device.attach, pid)
        script = bounded(session.create_script, bridge.read_text() + """
          rpc.exports={prepare(){return new Promise((resolve,reject)=>bridge.perform(()=>{
            try{bridge.deoptimizeEverything();resolve(true)}catch(error){reject(error)}
          }));}};
        """)
        bounded(script.load)
        assert bounded(script.exports_sync.prepare)
        bounded(script.unload)
        bounded(session.detach)
    source = bridge.read_text() + """
    let hits = 0;
    bridge.perform(() => {
      const methods = bridge.use('android.view.Choreographer').doFrame.overloads;
      for (const method of methods) method.implementation = function(...args) {
        hits++;
        return method.apply(this, args);
      };
    });
    rpc.exports = {count() {return hits;}};
    """
    output = ROOT / "out/audit" / ("frida-hot-unload-" + args.package + ".json")
    result = {"package": args.package, "pid": pid, "deoptimization": args.deopt, "cycles": [], "errors": []}
    try:
        for cycle in range(args.cycles):
            session = bounded(device.attach, pid)
            script = bounded(session.create_script, source)
            script.on("message", lambda m, d: result["errors"].append(m) if m.get("type") == "error" else None)
            try:
                bounded(script.load)
                deadline = time.monotonic() + 10
                hits = 0
                while hits < 10 and time.monotonic() < deadline:
                    time.sleep(0.1)
                    hits = bounded(script.exports_sync.count)
                assert hits >= 10, hits
                bounded(script.unload)
            finally:
                bounded(session.detach)
            time.sleep(0.1)
            assert str(pid) in adb.shell("pidof " + args.package, check=False).split(), "Target died after Java unload"
            assert not result["errors"], result["errors"]
            result["cycles"].append({"cycle": cycle + 1, "natural_frame_callbacks": hits})
            save_json(output, result)
        time.sleep(2)
        assert str(pid) in adb.shell("pidof " + args.package, check=False).split()
        result["passed"] = True
    except Exception as error:
        result.update(passed=False, error=str(error))
        raise
    finally:
        save_json(output, result)
        print(output)


if __name__ == "__main__":
    main()
