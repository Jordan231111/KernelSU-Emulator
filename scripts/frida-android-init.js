// SPDX-License-Identifier: MIT
// Load before hot Java hooks. Optimized callers can retain stale native hook
// paths after unload on ART. A process restart returns it to normal execution.
Java.perform(() => {
  Java.deoptimizeEverything();
  send({event: 'android-java-tracing-ready', pid: Process.id});
});
