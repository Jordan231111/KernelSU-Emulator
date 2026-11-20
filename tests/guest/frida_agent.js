// SPDX-License-Identifier: MIT
// Qualification uses owned buffers/functions/files; it does not change gameplay.
'use strict';
const keep = [];
const libc = Process.getModuleByName('libc.so');
const exp = name => libc.getExportByName(name);
const nf = (name, ret, args) => new NativeFunction(exp(name), ret, args);
function check(value, detail) { if (!value) throw new Error(detail); }
function javaCall(body) {
  return new Promise((resolve, reject) => Java.perform(() => {
    try { resolve(body()); } catch (error) { reject(error); }
  }));
}
let worker = null;
let stalkCounts = { calls: 0, blocks: 0 };

rpc.exports = {
  info() {
    return {version: Frida.version, runtime: Script.runtime, pid: Process.id,
      arch: Process.arch, platform: Process.platform, heap: Frida.heapSize,
      modules: Process.enumerateModules().length, threads: Process.enumerateThreads().length,
      uid: nf('getuid', 'uint', [])(), java: Java.available,
      kernelApi: Kernel.available, objc: typeof ObjC !== 'undefined' && ObjC.available};
  },
  echo(value) { return value; },
  async delayed(value) { await new Promise(r => setTimeout(r, 10)); return value; },
  binary() { return new Uint8Array([0, 1, 127, 128, 255]).buffer; },
  fail() { throw new Error('intentional-rpc-test'); },
  messaging() {
    recv('qualification', (message, data) => {
      send({kind: 'message-reply', value: message.value, bytes: data.byteLength}, data);
    });
    send({kind: 'message-ready'});
    return true;
  },
  native(count) {
    const cm = new CModule(`
      int add(int a, int b) { return a + b; }
      int read_int(int *p) { return *p; }
      int call_cb(int (*cb)(int), int v) { return cb(v); }
    `);
    const add = new NativeFunction(cm.add, 'int', ['int', 'int']);
    check(add(17, 25) === 42, 'CModule/NativeFunction');
    let seen = 0, backtrace = 0;
    const listener = Interceptor.attach(cm.add, {
      onEnter(args) {
        seen++;
        if (seen === 1) backtrace = Thread.backtrace(this.context, Backtracer.FUZZY).length;
      }
    });
    Interceptor.flush();
    for (let i = 0; i < count; i++) check(add(i, 7) === i + 7, 'attached original');
    listener.detach();
    Interceptor.flush();
    check(seen === count, 'native hook count ' + seen);
    const replacement = new NativeCallback((a, b) => a - b, 'int', ['int', 'int']);
    Interceptor.replace(cm.add, replacement);
    Interceptor.flush();
    check(add(40, 2) === 38, 'replace');
    Interceptor.revert(cm.add);
    Interceptor.flush();
    check(add(40, 2) === 42, 'revert');
    const callback = new NativeCallback(v => v * 3, 'int', ['int']);
    check(new NativeFunction(cm.call_cb, 'int', ['pointer', 'int'])(callback, 14) === 42, 'callback');
    const open = new SystemFunction(exp('open'), 'int', ['pointer', 'int']);
    const missing = open(Memory.allocUtf8String('/frida-qualification-no-such-file'), 0);
    check(missing.value === -1 && missing.errno === 2, 'SystemFunction errno');
    const parsed = Instruction.parse(cm.add);
    const matches = new ApiResolver('module').enumerateMatches('exports:libc.so!getpid');
    check(matches.length > 0 && new ModuleMap().find(exp('getpid')).name === 'libc.so', 'resolver');
    const symbol = DebugSymbol.fromAddress(exp('getpid')).toString();
    cm.dispose();
    return {calls: count, hooks: seen, replacedAndReverted: true, callback: 42,
      errno: missing.errno, instruction: parsed.toString(), backtrace, symbol};
  },
  async memory() {
    const p = Memory.alloc(Process.pageSize);
    p.writeU32(0x78563412);
    p.add(8).writeU64(uint64('18446744073709551600'));
    check(p.readU32() === 0x78563412 && p.add(8).readU64().toString() === '18446744073709551600', 'read/write');
    const sync = Memory.scanSync(p, 32, '12 34 56 78');
    let asyncMatches = 0;
    await new Promise((resolve, reject) => Memory.scan(p, 32, '12 34 56 78', {
      onMatch() { asyncMatches++; }, onError: reject, onComplete: resolve
    }));
    check(sync.length === 1 && asyncMatches === 1, 'scan');
    let accesses = 0;
    const cm = new CModule('int read_int(int *p) { return *p; }');
    MemoryAccessMonitor.enable({base: p, size: Process.pageSize}, {onAccess() { accesses++; }});
    try {
      // Let the process exception handler service the monitor's protection fault.
      new NativeFunction(cm.read_int, 'int', ['pointer'], {exceptions: 'propagate'})(p);
    } finally { MemoryAccessMonitor.disable(); }
    check(accesses > 0, 'memory access monitor');
    const code = Memory.alloc(Process.pageSize);
    check(Memory.protect(code, Process.pageSize, 'rwx'), 'protect');
    Memory.patchCode(code, 32, target => {
      const writer = new Arm64Writer(target, {pc: code});
      writer.putLdrRegU64('x0', uint64(42)); writer.putRet(); writer.flush(); writer.dispose();
    });
    check(new NativeFunction(code, 'int', [])() === 42, 'generated code');
    const relocated = Memory.alloc(Process.pageSize);
    const writer = new Arm64Writer(relocated);
    const relocator = new Arm64Relocator(code, writer);
    check(relocator.readOne() > 0, 'relocator read');
    relocator.writeOne(); writer.flush(); relocator.dispose(); writer.dispose();
    Cloak.addRange({base: code, size: Process.pageSize});
    check(Cloak.hasRangeContaining(code), 'cloak range');
    Cloak.removeRange({base: code, size: Process.pageSize});
    check(!Cloak.hasRangeContaining(code), 'uncloak range');
    cm.dispose();
    return {scanSync: sync.length, scanAsync: asyncMatches, accesses, generatedReturn: 42,
      rangeProtection: Process.findRangeByAddress(code).protection};
  },
  java(count) {
    return javaCall(() => {
      const System = Java.use('java.lang.System');
      const property = System.getProperty.overload('java.lang.String');
      let hooks = 0;
      property.implementation = function (key) {
        if (String(key) === 'ksu.frida.qualification') { hooks++; return 'qualified'; }
        return property.call(this, key);
      };
      let original;
      try {
        original = String(System.getProperty('java.version'));
        for (let i = 0; i < count; i++) check(String(System.getProperty('ksu.frida.qualification')) === 'qualified', 'Java hook');
      } finally { property.implementation = null; }
      check(hooks === count && System.getProperty('ksu.frida.qualification') === null, 'Java revert');
      const name = 'io.github.kernelsuemulator.frida.Q' + Date.now();
      const Q = Java.registerClass({name, fields: {value: 'int'}, methods: {
        twice: [{returnType: 'int', argumentTypes: ['int'], implementation(v) { return v * 2; }}]
      }});
      const object = Q.$new(); object.value.value = 21;
      check(object.twice(object.value.value) === 42, 'registerClass/field');
      const arr = Java.array('int', [1, 2, 3]);
      check(arr.length === 3 && arr[2] === 3, 'Java array');
      const cast = Java.cast(object, Java.use('java.lang.Object'));
      check(String(cast.getClass().getName()) === name, 'Java cast');
      const classes = Java.enumerateLoadedClassesSync();
      const loaders = Java.enumerateClassLoadersSync();
      const backtrace = Java.backtrace().frames.length;
      keep.push(Java.retain(object));
      return {hooks, original, registered: name, field: object.value.value,
        classes: classes.length, loaders: loaders.length, backtrace,
        androidVersion: Java.androidVersion, androidSdk: Java.use('android.os.Build$VERSION').SDK_INT.value,
        cache: String(Java.use('android.app.ActivityThread').currentApplication().getCacheDir().getAbsolutePath())};
    });
  },
  javaMain() {
    return new Promise((resolve, reject) => Java.perform(() => Java.scheduleOnMainThread(() => {
      try { resolve({mainThread: Java.isMainThread(), uptime: Number(Java.use('android.os.SystemClock').uptimeMillis())}); }
      catch (error) { reject(error); }
    })));
  },
  javaChoose(name) {
    return new Promise((resolve, reject) => Java.perform(() => {
      let count = 0;
      try { Java.choose(name, {onMatch() { count++; }, onComplete() { resolve(count); }}); }
      catch (error) { reject(error); }
    }));
  },
  traceTick(count) {
    return javaCall(() => {
      const Clock = Java.use('android.os.SystemClock');
      const getpid = nf('getpid', 'int', []);
      for (let i = 0; i < count; i++) { Clock.uptimeMillis(); getpid(); }
      return count;
    });
  },
  deoptimize() { return javaCall(() => {
    Java.deoptimizeEverything();
    return {enabled: Java.api.artInstrumentation.add(336).readU8()};
  }); },
  async files(cache) {
    const path = cache + '/ksu-frida-qa-' + Process.id;
    const bytes = new Uint8Array([0, 1, 127, 128, 255]);
    const f = new File(path, 'wb'); f.write(bytes.buffer); f.flush(); f.close();
    const data = new Uint8Array(File.readAllBytes(path));
    check(data.join(',') === bytes.join(','), 'File binary roundtrip');
    const db = SqliteDatabase.open(path + '.db');
    db.exec('CREATE TABLE checks (value TEXT)');
    const insert = db.prepare('INSERT INTO checks VALUES (?)'); insert.bindText(1, 'qualified'); insert.step();
    const select = db.prepare('SELECT value FROM checks'); check(select.step()[0] === 'qualified', 'SQLite');
    db.close();
    const unlink = nf('unlink', 'int', ['pointer']);
    unlink(Memory.allocUtf8String(path)); unlink(Memory.allocUtf8String(path + '.db'));
    const pipeFds = Memory.alloc(8);
    check(nf('pipe', 'int', ['pointer'])(pipeFds) === 0, 'pipe');
    const input = new UnixInputStream(pipeFds.readS32(), {autoClose: true});
    const output = new UnixOutputStream(pipeFds.add(4).readS32(), {autoClose: true});
    await output.writeAll(bytes.buffer);
    check(new Uint8Array(await input.readAll(5)).join(',') === bytes.join(','), 'streams');
    await input.close(); await output.close();
    return {file: true, sqlite: true, streams: true};
  },
  async socket() {
    const listener = await Socket.listen({family: 'ipv4', host: '127.0.0.1', port: 0});
    const accept = listener.accept();
    const client = await Socket.connect({family: 'ipv4', host: '127.0.0.1', port: listener.port});
    const server = await accept;
    await client.output.writeAll(new Uint8Array([42]).buffer);
    check(new Uint8Array(await server.input.readAll(1))[0] === 42, 'socket data');
    await client.close(); await server.close(); await listener.close();
    return true;
  },
  startWorker() {
    check(worker === null, 'worker already active');
    const state = Memory.alloc(20);
    const cm = new CModule(`
      #include <stdint.h>
      extern int gettid(void); extern int usleep(unsigned int);
      extern volatile int tid, go, done, stop;
      extern volatile unsigned int total;
      unsigned int step(unsigned int i) { return i * 3 + 1; }
      void *run(void *unused) {
        tid = gettid();
        while (!go && !stop) usleep(1000);
        for (unsigned int i = 0; i < 1000 && !stop; i++) total += step(i);
        done = 1;
        while (!stop) usleep(1000);
        return 0;
      }
    `, {gettid: exp('gettid'), usleep: exp('usleep'),
      tid: state, go: state.add(4), done: state.add(8), stop: state.add(12), total: state.add(16)});
    const thread = Memory.alloc(8);
    const err = nf('pthread_create', 'int', ['pointer', 'pointer', 'pointer', 'pointer'])(thread, NULL, cm.run, NULL);
    check(err === 0, 'pthread_create ' + err);
    worker = {cm, thread, state};
    return true;
  },
  workerStatus() { return worker === null ? null : {tid: worker.state.readS32(), done: worker.state.add(8).readS32(), total: worker.state.add(16).readU32()}; },
  followWorker() {
    const tid = worker.state.readS32(); check(tid > 0, 'worker tid');
    stalkCounts = {calls: 0, blocks: 0};
    Stalker.follow(tid, {events: {call: true, block: true}, onReceive(events) {
      for (const event of Stalker.parse(events, {annotate: true, stringify: false})) {
        if (event[0] === 'call') stalkCounts.calls++; else if (event[0] === 'block') stalkCounts.blocks++;
      }
    }});
    return tid;
  },
  goWorker() { worker.state.add(4).writeS32(1); return true; },
  unfollowWorker() { Stalker.unfollow(worker.state.readS32()); Stalker.flush(); return true; },
  stopWorker() {
    const result = {...stalkCounts, tid: worker.state.readS32(), done: worker.state.add(8).readS32(), total: worker.state.add(16).readU32()};
    worker.state.add(12).writeS32(1);
    check(nf('pthread_join', 'int', ['ulong', 'pointer'])(worker.thread.readU64(), NULL) === 0, 'pthread_join');
    worker.cm.dispose(); worker = null; Stalker.garbageCollect();
    return result;
  },
  il2cpp() {
    const module = Process.getModuleByName('libil2cpp.so');
    const domain = new NativeFunction(module.getExportByName('il2cpp_domain_get'), 'pointer', [])();
    const corlib = new NativeFunction(module.getExportByName('il2cpp_get_corlib'), 'pointer', [])();
    const name = new NativeFunction(module.getExportByName('il2cpp_image_get_name'), 'pointer', ['pointer'])(corlib).readUtf8String();
    check(!domain.isNull() && name.length > 0, 'IL2CPP public API');
    return {module: module.name, domainPresent: true, coreLibrary: name};
  },
  cleanup() { keep.splice(0).forEach(o => o.$dispose()); gc(); return {heap: Frida.heapSize}; }
};
