# SPDX-License-Identifier: MIT
"""Frida-tools file watching fallback for the measured Darwin GIO failure.

One worker checks metadata every 0.5 s, irrespective of the number of monitors.
Only files explicitly watched by the active REPL/tracer are visited; contents
are read by those tools only after a change. Other platforms use Frida's native
monitor. No guest process, instrumentation or filesystem permissions change.
"""
import os
import sys
import threading
import traceback
from pathlib import Path

import frida

_lock = threading.Lock()
_monitors = set()
_worker = None
_wake = threading.Event()


def _run():
    global _worker
    while True:
        _wake.wait(0.5)
        _wake.clear()
        with _lock:
            active = tuple(_monitors)
            if not active:
                _worker = None
                return
        for monitor in active:
            monitor._check()


class PollingFileMonitor:
    def __init__(self, path):
        self.path = os.fsdecode(os.path.abspath(path))
        self._callbacks = []
        self._state = {}
        self._enabled = False

    def on(self, signal, callback):
        if signal != "change":
            raise ValueError("Unknown FileMonitor signal: " + signal)
        self._callbacks.append(callback)

    def off(self, signal, callback):
        if signal != "change":
            raise ValueError("Unknown FileMonitor signal: " + signal)
        self._callbacks.remove(callback)

    def _snapshot(self):
        path = Path(self.path)
        try:
            paths = list(path.iterdir()) if path.is_dir() else [path]
        except OSError:
            return {}
        result = {}
        for item in paths:
            try:
                stat = item.lstat()
                result[str(item)] = (stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
            except OSError:
                pass  # Editors can replace entries or change access mid-scan.
        return result

    def enable(self):
        global _worker
        with _lock:
            if self._enabled:
                return
            self._state = self._snapshot()
            self._enabled = True
            _monitors.add(self)
            if _worker is None:
                _worker = threading.Thread(target=_run, name="frida-file-watch", daemon=True)
                _worker.start()

    def disable(self):
        with _lock:
            self._enabled = False
            _monitors.discard(self)
        _wake.set()

    def _check(self):
        if not self._enabled:
            return
        try:
            current = self._snapshot()
            previous, self._state = self._state, current
            for path in current.keys() | previous.keys():
                if not self._enabled:
                    return
                if current.get(path) == previous.get(path):
                    continue
                kind = "created" if path not in previous else "deleted" if path not in current else "changed"
                for callback in tuple(self._callbacks):
                    callback(path, "", kind)
        except Exception:
            traceback.print_exc()


FileMonitor = PollingFileMonitor if sys.platform == "darwin" else frida.FileMonitor
