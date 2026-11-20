#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correct Android 12L offsets and ART deoptimization synchronization.

Use the Python belonging to the existing Frida environment. No packages are
installed. Android 12 and 12L have the same AOSP instrumentation layout; MuMu's
EnableDeoptimization reads/writes [this + 0x150]. Only the missing API-32 entry
is added. ART requires its exclusive mutator lock while installing deoptimization
stubs; use the bridge's existing suspend/resume helper around that operation.
Use the same exclusion while reverting method and quick-code hooks; release JNI
references after resuming the threads.
The existing compatibility changes in other Frida files are retained.
"""
import hashlib
import importlib.metadata
from pathlib import Path

import frida
import frida_tools

BEFORE = "b3e38898cfb44f0ceab6d6b6e03ac94620bcff3c7dfef73b0953bbc95ac0e4ee"
OLD = '"8-31":336}'
NEW = '"8-31":336,"8-32":336}'
CALLS = [
    ('case 3:o["art::Instrumentation::DeoptimizeEverything"](e,Memory.allocUtf8String("frida"));',
     'case 3:it(()=>o["art::Instrumentation::DeoptimizeEverything"](e,Memory.allocUtf8String("frida")));'),
    ('case 5:o["art::Instrumentation::Deoptimize"](e,r);',
     'case 5:it(()=>o["art::Instrumentation::Deoptimize"](e,r));'),
    ('_dispose(e){Array.from(this._patchedMethods).forEach(e=>{e.implementation=null}),this._patchedMethods.clear(),St(),this._classHandles.dispose(e),this._classes={}}',
     '_dispose(e){const t=()=>{Array.from(this._patchedMethods).forEach(e=>{e.implementation=null}),this._patchedMethods.clear(),St()};ko?it(t):t(),this._classHandles.dispose(e),this._classes={}}'),
]


def main():
    if frida.__version__ != "17.26.3" or importlib.metadata.version("frida-tools") != "14.13.1":
        raise SystemExit("This measured correction targets Frida 17.26.3 / tools 14.13.1")
    path = Path(frida_tools.__file__).parent / "bridges/java.js"
    data = path.read_bytes()
    original = data.replace(NEW.encode(), OLD.encode())
    for old, new in CALLS:
        original = original.replace(new.encode(), old.encode())
    if hashlib.sha256(original).hexdigest() != BEFORE or original.count(OLD.encode()) != 1:
        raise SystemExit("The Java bridge differs from the qualified source; inspect it before changing offsets")
    fixed = original.replace(OLD.encode(), NEW.encode())
    for old, new in CALLS:
        if fixed.count(old.encode()) != 1:
            raise SystemExit("Deoptimization call site changed")
        fixed = fixed.replace(old.encode(), new.encode())
    if fixed != data:
        path.write_bytes(fixed)
    print(f"Android 12L ARM64 Java bridge qualified: {path}")
    print("SHA-256: " + hashlib.sha256(fixed).hexdigest())


if __name__ == "__main__":
    main()
