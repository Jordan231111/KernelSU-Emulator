// SPDX-License-Identifier: MIT
// REPL helpers; module names and queries come from the current target.
globalThis.findModules = (pattern = '') => Process.enumerateModules()
  .filter(m => m.name.toLowerCase().includes(pattern.toLowerCase()))
  .map(m => ({name: m.name, base: m.base, size: m.size, path: m.path}));

globalThis.findNative = query => new ApiResolver('module').enumerateMatches(query)
  .map(entry => {
    const module = Process.findModuleByAddress(entry.address);
    return {...entry, module: module?.name, rva: module ? entry.address.sub(module.base) : null};
  });

globalThis.findJava = query => new Promise((resolve, reject) => Java.perform(() => {
  try { resolve(Java.enumerateMethods(query)); } catch (error) { reject(error); }
}));

globalThis.captureTraceRange = (moduleName, symbolName) => new Promise(resolve => {
  const start = Process.getModuleByName(moduleName).getExportByName(symbolName);
  const hook = Interceptor.attach(start, {onEnter() {
    const result = {start: start.toString(), end: this.returnAddress.toString(), tid: this.threadId};
    hook.detach();
    resolve(result);
  }});
});
