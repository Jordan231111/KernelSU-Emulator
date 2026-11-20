// SPDX-License-Identifier: MIT
// Full TLS plaintext capture. Load frida-android-init.js first for Java hooks.
// Native providers are discovered as modules load. Event labels distinguish an
// outgoing attempt from bytes actually received; failed writes may be logged.
const tlsHooks = new Map();
function tlsCapture(buffer, length, details) {
  for (let offset = 0; offset < length; offset += 65536) {
    const size = Math.min(65536, length - offset);
    send({...details, offset, totalLength: length}, buffer.add(offset).readByteArray(size));
  }
}
function tlsCaller(address) {
  const module = Process.findModuleByAddress(address);
  return {address: address.toString(), module: module?.name,
    rva: module ? address.sub(module.base).toString() : null};
}
const tlsObserver = Process.attachModuleObserver({onAdded(module) {
  for (const symbol of ['SSL_write', 'SSL_read', 'SSL_write_ex', 'SSL_read_ex',
                        'wolfSSL_write', 'wolfSSL_read', 'mbedtls_ssl_write', 'mbedtls_ssl_read',
                        'gnutls_record_send', 'gnutls_record_recv']) {
    const address = module.findExportByName(symbol);
    if (address === null || tlsHooks.has(address.toString())) continue;
    const outgoing = /write|send/.test(symbol), extended = symbol.endsWith('_ex');
    const listener = Interceptor.attach(address, {
      onEnter(args) {
        this.buffer = args[1];
        this.count = args[2].toUInt32();
        this.actual = args[3];
        this.details = {event: 'tls-plaintext', direction: outgoing ? 'out-attempt' : 'in',
          provider: module.name, function: symbol, caller: tlsCaller(this.returnAddress)};
        if (outgoing) tlsCapture(this.buffer, this.count, this.details);
      },
      onLeave(retval) {
        if (outgoing || retval.toInt32() <= 0) return;
        const count = extended ? (Process.pointerSize === 8 ? this.actual.readU64().toNumber() : this.actual.readU32()) : retval.toInt32();
        tlsCapture(this.buffer, count, this.details);
      }
    });
    tlsHooks.set(address.toString(), {module: module.base.toString(), listener});
    send({event: 'tls-hook', provider: module.name, function: symbol});
  }
}, onRemoved(module) {
  for (const [address, hook] of tlsHooks) if (hook.module === module.base.toString()) {
    hook.listener.detach(); tlsHooks.delete(address);
  }
}});

Java.perform(() => {
  for (const prefix of ['com.android.org.conscrypt.', 'org.conscrypt.']) {
    for (const socket of ['ConscryptEngineSocket', 'ConscryptFileDescriptorSocket']) {
      for (const [suffix, method, outgoing] of [['$SSLOutputStream', 'write', true], ['$SSLInputStream', 'read', false]]) {
        const name = prefix + socket + suffix;
        try {
          const target = Java.use(name)[method].overload('[B', 'int', 'int');
          const capture = (bytes, offset, count) => {
            if (count <= 0) return;
            const result = new Uint8Array(count);
            for (let i = 0; i < count; i++) result[i] = bytes[offset + i] & 255;
            send({event: 'tls-plaintext', direction: outgoing ? 'out-attempt' : 'in', provider: name, function: method}, result.buffer);
          };
          target.implementation = function(bytes, offset, count) {
            if (outgoing) capture(bytes, offset, count);
            const result = target.call(this, bytes, offset, count);
            if (!outgoing) capture(bytes, offset, result);
            return result;
          };
          send({event: 'tls-hook', provider: name, function: method});
        } catch (error) {
          // This provider is absent or uses a different overload on this build.
        }
      }
    }
  }
});
