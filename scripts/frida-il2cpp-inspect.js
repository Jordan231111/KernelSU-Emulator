// SPDX-License-Identifier: MIT
// Load the existing frida-il2cpp-bridge dist/index.js first.
globalThis.findManaged = (assemblyPattern, classPattern, methodPattern) => Il2Cpp.perform(() => {
  const result = [];
  for (const assembly of Il2Cpp.domain.assemblies) {
    if (!assembly.name.includes(assemblyPattern)) continue;
    for (const klass of assembly.image.classes) {
      if (!klass.fullName.includes(classPattern)) continue;
      for (const method of klass.methods) {
        if (!method.name.includes(methodPattern)) continue;
        result.push({assembly: assembly.name, type: klass.fullName, method: method.name,
          parameters: method.parameters.map(p => p.type.name), returns: method.returnType.name,
          address: method.virtualAddress.toString(), rva: method.relativeVirtualAddress.toString()});
      }
    }
  }
  return result;
});

globalThis.describeManagedType = (assemblyName, className) => Il2Cpp.perform(() => {
  const klass = Il2Cpp.domain.assembly(assemblyName).image.class(className);
  return {name: klass.fullName, fields: klass.fields.map(f => ({name: f.name,
    type: f.type.name, offset: f.offset, static: f.isStatic})),
    methods: klass.methods.map(m => ({name: m.name, parameters: m.parameters.map(p => p.type.name),
      returns: m.returnType.name, address: m.virtualAddress.toString(), rva: m.relativeVirtualAddress.toString()}))};
});

globalThis.traceManaged = (assemblyName, className, methodName, detailed = true, threadId = null) => Il2Cpp.perform(() => {
  const methods = Il2Cpp.domain.assembly(assemblyName).image.class(className).methods
    .filter(m => m.name === methodName && !m.virtualAddress.isNull());
  if (methods.length === 0) throw new Error('No matching executable method');
  let tracer = Il2Cpp.trace(detailed);
  if (threadId !== null) {
    const thread = Il2Cpp.attachedThreads.find(t => t.id === threadId);
    if (!thread) throw new Error('No attached IL2CPP thread with that ID');
    tracer = tracer.thread(thread);
  }
  tracer.verbose(true).methods(...methods).and().attach();
  return methods.map(m => ({name: m.name, rva: m.relativeVirtualAddress.toString()}));
});
