#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install the qualified local-file watcher in the existing Frida-tools copy."""
import hashlib
import importlib.metadata
import sys
from pathlib import Path

import frida_tools

ORIGINALS = {
    "tracer.py": "7364d519f6262caaba4d997e8911f50e03872f914f66db5cdd2cfee0525509d7",
    "repl.py": "462ea3450e88bef96af8bfee4f276b46a0a840079b00f715a7b7d2a4d98452b2",
}
IMPORT = "from frida_tools._compat_file_monitor import FileMonitor\n"


def main():
    if sys.platform != "darwin":
        print("Native file watching retained on this platform")
        return
    if importlib.metadata.version("frida-tools") != "14.13.1":
        raise SystemExit("This correction targets frida-tools 14.13.1")
    root = Path(frida_tools.__file__).parent
    updates = []
    for name, checksum in ORIGINALS.items():
        path = root / name
        original = path.read_text().replace(IMPORT, "").replace("monitor = FileMonitor(", "monitor = frida.FileMonitor(")
        if hashlib.sha256(original.encode()).hexdigest() != checksum:
            raise SystemExit("Unexpected Frida source: " + str(path))
        fixed = original.replace("import frida\n", "import frida\n" + IMPORT, 1)
        fixed = fixed.replace("monitor = frida.FileMonitor(", "monitor = FileMonitor(")
        updates.append((path, fixed))
    (root / "_compat_file_monitor.py").write_bytes(Path(__file__).with_name("frida_file_monitor.py").read_bytes())
    for path, source in updates:
        path.write_text(source)
    print("Darwin Frida REPL/tracer file watching installed: " + str(root))


if __name__ == "__main__":
    main()
