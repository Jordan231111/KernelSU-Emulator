# Frida on the qualified MuMu installation

The existing desktop client/Python **17.26.3**, frida-tools **14.13.1**, and
matching undetected-frida Android kit remain installed. No second client or
server version was installed. The local inventory is `~/Documents/temp/RE_TOOLS_INVENTORY.md`.

Upstream Frida 17.27.3 is newer. This audit retains the user's matched 17.26.3
client/server/gadget/inject set and its measured ELF-discovery, libc, stat-reader,
TinyCC/Capstone, instruction-trace and CLI lifecycle corrections. The later
[release notes](https://frida.re/news/2026/11/19/frida-17-27-3-released/)
do not establish a repair for the Java/child-gating failure reproduced below.
Upgrading one binary would discard the qualified pairing without establishing
compatibility of the other components.

## Device setup and Gadget

Set `RE_ANDROID_SERIAL` from `adb devices -l` and `RE_TARGET_APP` to the Android
package identifier. Connect TCP devices with `adb connect "$RE_ANDROID_SERIAL"`.
MuMu's ADB port can change after restart. Set
`RE_FRIDA_SCRIPTS="$HOME/Documents/KernelSU-Emulator/scripts"` for the examples below.

Instance 0 already has `/data/local/tmp/uf-server`. A normal emulator restart
preserves this file and its permissions but stops its process. Reconnect to the
current ADB port and start the server again; the inventory's Everyday use block
does both and installs the binary only when missing or non-executable. Repeating
that block reuses the running server. A userdata reset requires installation again.
To deploy or replace it from the matching ARM64 kit:

    adb devices -l
    adb -s "$RE_ANDROID_SERIAL" push "$HOME/Documents/temp/undetected-frida-17.26.3/undetected-frida-server-17.26.3-android-arm64" /data/local/tmp/uf-server.new
    adb -s "$RE_ANDROID_SERIAL" shell "su -c 'pkill -x uf-server || true'"
    adb -s "$RE_ANDROID_SERIAL" shell "su -c 'chmod 755 /data/local/tmp/uf-server.new && mv /data/local/tmp/uf-server.new /data/local/tmp/uf-server'"
    adb -s "$RE_ANDROID_SERIAL" shell "su -c '/data/local/tmp/uf-server -D </dev/null >/dev/null 2>&1'"
    adb -s "$RE_ANDROID_SERIAL" shell "su -c 'ps -A -o USER,PID,NAME,ARGS | grep [u]f-server'"

Run the server as root through the quoted `su -c` commands; remove `-D` and the
output redirection when diagnosing startup errors. The ARM64 server includes
matching 32-bit support. Use the ARM server on a 32-bit device and select
inject/Gadget libraries for the target process ABI.

The device source is
`~/Tools/RE/zygisk/undetected-frida-17.26.3`, with its ELF/library-discovery
compatibility changes. Rebuild using
`~/Tools/RE/zygisk/undetected-frida-17.26.3/compat/build-android.sh [arm|arm64]`.

### Zygisk Gadget fallback

Use the matching kit ZIP, `undetected-frida-zygisk-17.26.3-v1.9.0.zip`, when server
injection fails. KernelSU installation: `adb -s "$RE_ANDROID_SERIAL" shell "su -c '/data/adb/ksu/bin/ksud module install /data/local/tmp/uf-zygisk.zip'"` after pushing that ZIP to `/data/local/tmp/uf-zygisk.zip`; reboot once after installation.

[ZygiskFrida](https://github.com/lico-n/ZygiskFrida/blob/v1.9.0/docs/advanced_config.md)
reads `/data/local/tmp/re.zyg.fri/config.json`. Merge an entry for `RE_TARGET_APP`
into its `targets` array; use `enabled: true`, `start_up_delay_ms: 0`,
`injected_libraries: [{"path":"/data/local/tmp/re.zyg.fri/libgadget.so"}]`, and
`child_gating: {"enabled":false,"mode":"freeze","injected_libraries":[]}`.
All three child-gating fields are required even when disabled.
[Gadget](https://frida.re/docs/gadget/) separately reads
`/data/local/tmp/re.zyg.fri/libgadget.config.so`:
`{"interaction":{"type":"listen","address":"127.0.0.1","port":27043,"on_load":"resume"},"runtime":"qjs"}`.
For a 32-bit target on a 64-bit device, use `libgadget32.so` and
`libgadget32.config.so`. `on_load: wait` blocks startup.
Apply the two prepared JSON files and restart only the target:

    adb -s "$RE_ANDROID_SERIAL" shell -T "su -c 'cat > /data/local/tmp/re.zyg.fri/config.json'" < config.json
    adb -s "$RE_ANDROID_SERIAL" shell -T "su -c 'cat > /data/local/tmp/re.zyg.fri/libgadget.config.so'" < libgadget.config.so
    adb -s "$RE_ANDROID_SERIAL" shell "su -c 'chmod 644 /data/local/tmp/re.zyg.fri/config.json /data/local/tmp/re.zyg.fri/libgadget.config.so'"
    adb -s "$RE_ANDROID_SERIAL" shell am force-stop "$RE_TARGET_APP"
    RE_ACTIVITY=$(adb -s "$RE_ANDROID_SERIAL" shell cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER "$RE_TARGET_APP" | tr -d '\r' | tail -n 1)
    adb -s "$RE_ANDROID_SERIAL" shell am start -W -n "$RE_ACTIVITY"
    adb -s "$RE_ANDROID_SERIAL" forward tcp:27053 tcp:27043
    frida-ps -H 127.0.0.1:27053
    frida -H 127.0.0.1:27053 -n Gadget --runtime=qjs -l "$RE_FRIDA_SCRIPTS/frida-android-init.js" -l script.js
    frida-trace -H 127.0.0.1:27053 -n Gadget -S "$RE_FRIDA_SCRIPTS/frida-android-init.js" -i 'libc.so!getaddrinfo' -j 'android.os.SystemClock!uptimeMillis'
    frida -H 127.0.0.1:27053 -n Gadget -q -e 'Process.enumerateThreads().map(t => ({id:t.id,name:t.name}))'
    frida-itrace -H 127.0.0.1:27053 -n Gadget -t "$RE_APP_TID" -o trace.itrace
    frida-il2cpp-bridge -H 127.0.0.1:27053 -n Gadget dump --out-dir dumps

For Python use `frida.get_device_manager().add_remote_device("127.0.0.1:27053")`.
The Gadget endpoint lists only its own process. Set `RE_APP_TID` from the thread
list to an application thread; exclude the agent's GumJS loop. Allow localhost
replies when using per-UID outbound firewall rules. Change the target's `enabled` to `false`
and restart it to disable injection. A successful attach does not establish that
the target permits sustained instrumentation.

## Loading the MuMu Java bridge from Python

The REPL and tracer use the locally patched `frida-tools` bridge. A separately
bundled npm `frida-java-bridge` does not inherit those changes. With an attached
`session`, load the installed bridge explicitly before a standalone agent:

```python
from pathlib import Path
import frida_tools

bridge = (Path(frida_tools.__file__).parent / "bridges/java.js").read_text()
source = bridge + "\nglobalThis.Java = bridge;\n" + Path("agent.js").read_text()
script = session.create_script(source, runtime="qjs")
script.load()
```

For portable agents, import `Java` from the project's `frida-java-bridge` npm
dependency and build with `frida-compile agent.ts -o agent.js`; qualify that
bridge's ART support separately. Current API syntax uses
`Process.getModuleByName(...).getExportByName(...)`, pointer read/write methods
and array-returning `Process.enumerateModules()`.

## NeoZygisk compatibility

The loader source is
`~/Tools/RE/zygisk/NeoZygisk-frida-compat-pr182-2.4-298`. Instance 0 uses upstream
`cc0bbba` plus the mutable-map correction and
[PR #182](https://github.com/JingMatrix/NeoZygisk/pull/182)'s executable-page
correction, version `v2.4 (301-cc0bbba-frida-compat-pr182)`.
`patches/neozygisk-frida-compat.patch` contains both corrections relative to that
upstream commit. Preserve both when rebuilding: they address different mapping
permissions. The tested configuration keeps SELinux enforcing and AVC spoofing Off.

## Reproducible corrections

After reinstalling Frida 17.26.3 / tools 14.13.1, run these from this repository
with the Python belonging to the existing Frida environment:

```sh
RE_FRIDA_PYTHON=/opt/homebrew/opt/python@3.11/bin/python3.11
"$RE_FRIDA_PYTHON" "$HOME/Tools/RE/zygisk/undetected-frida-17.26.3/compat/fix-frida-tools.py"
"$RE_FRIDA_PYTHON" scripts/fix-frida-java-bridge.py
"$RE_FRIDA_PYTHON" scripts/fix-frida-file-watch.py
```

For the existing IL2CPP CLI environment, set `RE_FRIDA_PYTHON` to
`~/Tools/RE/venvs/frida-il2cpp-bridge-0.14.0/bin/python` instead.
The two repository scripts check the exact tools version and qualified original
source before editing. They preserve the other installed compatibility changes.
These repair host tools; installing KernelSU alone does not apply them.

The Java correction supplies the missing API-32 ARM64 Instrumentation offset
`0x150`, measured from MuMu's actual `EnableDeoptimization` instructions and
cross-checked against Android 12/12L source. It holds ART's mutator lock through
the bridge's existing suspend/resume helper during deoptimization and method
patch teardown. `Java.deoptimizeEverything()` now passes in the diagnostic APK
and Epic Conquest 2. The qualified bundled bridge SHA-256 is
`0d63427b4281cacbf14b79824038bf150dc93478042c05f8f7637c073c60a127`.

Hot Java tracing uses `scripts/frida-android-init.js` before installing hooks.
Deoptimization prevents optimized callers from retaining stale hook paths after
unload. It affects only the instrumented process, and a process restart clears
that state. Native trace hooks call the original implementation. The final
lifecycle suite repeatedly unloads real Choreographer frame hooks while the game
continues rendering.

The macOS REPL/tracer file monitor did not deliver live changes reliably. Its
replacement checks metadata for explicitly watched files with one shared worker
every 0.5 seconds. Live trace-handler reload and compiler watch were exercised;
no guest filesystem permissions or app configuration change.

The r2frida Android initialization bug concatenated `modulebase` and `jniEnv`
into one invalid number. `patches/r2frida-6.2.6-info.patch` emits separate flags.
The existing 6.2.6 plugin at source `6f9091ebe9273a85c42e37245be8b50cdce6008d`
was rebuilt with the existing 17.26.3 devkit and installed in its existing path.
The corrected plugin reads `7f 45 4c 46` at EC2's module base without errors.
Its SHA-256 is `4fa34dde446548e659bb22ffb8007fa1d22d85f8fb683b03f0f525380337a0ed`.
To reproduce in `~/.local/share/radare2/r2pm/git/r2frida`, apply the patch, run
`make config.h`, `make -j4`, and `make user-install`. No new checkout is needed.

## Measured feature coverage

The named application was **Epic Conquest 2 3.1.5/code 509**,
`com.GacoGames.EC2`, ARM64, Unity **6000.3.8f1**. These results come from that
process unless the table says otherwise. Root belongs to the instrumentation
server; the app remains an ordinary app UID.

| Feature | Expected and observed |
| --- | --- |
| Attach, unload, detach, reconnect | Matching PID and working RPC after a fresh session; passed |
| Emulator restart and inventory commands | Two cold boots: the original start command and the revised complete reconnect/start block both pass. The revised block discovers the changed port without a prior ADB connection, preserves the server hash, and reuses one PID when repeated. EC2 Java/native/RPC and detach pass afterward |
| Spawn/resume | Attach while paused, resume and retain a live app; passed |
| Session stress | 500 complete attach/load/RPC/unload/detach cycles in EC2; 200 in the diagnostic APK; passed |
| Native instrumentation | 100,000 original calls and 100,000 hook callbacks, CModule, replacement/revert, NativeCallback, errno, symbols and instruction parsing; passed |
| Java instrumentation | 10,000 conditional hooks, original calls, revert, fields, arrays, class registration, class loaders, casts, heap enumeration and main-thread scheduling; passed |
| Java stacks | A real Java Thread callback produces the diagnostic method and Thread.run frames; passed |
| RPC/messaging | Structured values, promises, binary values, deliberate RPC exception and bidirectional binary messaging; passed |
| Memory | Owned-buffer reads/writes/scans, protection, ARM64 generated code returning 42, relocation, access monitor and Cloak; passed |
| Files, SQLite, streams, sockets | Own scratch-file/database/pipe and loopback roundtrips; passed |
| QJS/V8 and bytecode | Both runtimes, QJS bytecode and script unload; passed |
| JavaScript Worker | Separate ES-module worker returns 42 through RPC and terminates; passed. Flattening its module with an ordinary bundle loses its worker entrypoint, so the fixture preserves separate modules |
| Stalker | Owned native worker produces call/block events, then unfollows, joins and completes; passed |
| Library injection | File and blob injection run the diagnostic entrypoint, produce the expected own-cache marker and unload; passed |
| Live CLI traces | Actual EGL/Vulkan and Java frame calls, handler reload, instruction trace with nonempty ITR2 chunks, clean stop and surviving game; passed |
| CLI file transfer | 1 MiB push/list/pull/remove, identical SHA-256; passed |
| Persistent session | A test-only TCP transport is broken, Session.resume reconnects, and RPC counter continues from 1 to 2; passed |
| IL2CPP | Native domain/core-library APIs; bridge enumerates 114 assemblies, finds UnityEngine.Time.get_deltaTime, invokes it on Unity's main thread and traces it; passed |
| TLS/helper examples | Diagnostic APK only: native/Java lookup helpers and a controlled unauthenticated example.com request. Native BoringSSL and Java Conscrypt hooks observe the known request and response. No game traffic or add-on configuration is captured; passed |
| Child gating with native instrumentation | Unload Java preparation, gate the app's child, call native RPC in it, resume, and observe exit 23; passed |
| Child gating with an active Java bridge | Expected exit 23; observed child SIGSEGV/exit 139 while the parent survives. Reproduced with QJS and V8. Ordinary ungated child execution passes. Global deoptimization and trial inherited-VM cleanup guards did not repair it; those guards were not installed |
| frida-strace | Fails to start; guest has no `/sys/kernel/btf/vmlinux`. This 4.19 kernel lacks the BTF/ring-buffer environment required by the syscall tracer; native function tracing works |
| RustModule / Kernel API | This installed Android agent has no RustModule global and reports Kernel.available=false. These are not qualified capabilities of this server build |

The Java/child-gating combination is a remaining upstream compatibility defect,
consistent with [Frida issue 2422](https://github.com/frida/frida/issues/2422).
The passing native-only sequence is a usable workflow, not proof that the failing
combination has been fixed. The audit therefore does **not** claim every Frida
API or every combination works. ObjC/Swift, Windows APIs and non-ARM64 instruction
writers are not Android ARM64 features.

For Java sessions, leave `Session.enable_child_gating()` unused, or call
`session.disable_child_gating()` if enabled. Without gating, ordinary child
execution works; attaching later can miss early calls or short-lived helpers.
For the passing native sequence, unload and detach Java agents first, attach a
native-only session, enable gating, instrument the child, then resume it before
detaching. Normal `-f` app spawning does not require this child-gating sequence.
Objection and DEXDump bundle separate agents; the core coverage above does not
establish that every command in those tools works or patch their Java bridges.

## Repeating the checks

Use the existing matching server from the inventory, with authorized Shell root.
Build and install the diagnostic APK when testing it; the Frida harness does not
grant it root. Build test fixtures with `bash tests/guest/build-frida-fixtures.sh`.

```sh
/opt/homebrew/opt/python@3.11/bin/python3.11 tests/guest/qualify_frida.py --instance 0 --package com.GacoGames.EC2 --cycles 500
/opt/homebrew/opt/python@3.11/bin/python3.11 tests/guest/qualify_frida_cli.py --instance 0 --package com.GacoGames.EC2 --seconds 20 --filesystem
/opt/homebrew/opt/python@3.11/bin/python3.11 tests/guest/qualify_frida_lifecycle.py --instance 0 --package com.GacoGames.EC2 --cycles 100
/opt/homebrew/opt/python@3.11/bin/python3.11 tests/guest/qualify_frida_extra.py --instance 0 --package com.GacoGames.EC2
/opt/homebrew/opt/python@3.11/bin/python3.11 tests/guest/qualify_frida_helpers.py --instance 0
```

Run guest/UI suites sequentially: they share the foreground activity. The extra
suite returns failure for the unresolved Java/child-gating case instead of
turning it into a pass. `--case native_child_gating` isolates the working sequence.
The scripts record expected/observed results in ignored `out/audit/`; raw captures
remain local. Restart the selected target after hot tracing to clear temporary
classes and deoptimization. No gameplay values, saves or add-on configurations
are modified.
