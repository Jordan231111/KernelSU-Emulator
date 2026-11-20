#!/usr/bin/env python3
"""Test helper APIs and TLS observation using only the diagnostic app's traffic."""
import argparse
import hashlib
import sys
import time
from pathlib import Path

import frida
import frida_tools

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ksu_emulator.common import ROOT, save_json
from ksu_emulator.mumu import MuMu
from qualify_frida import bounded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--instance', required=True, type=int)
    args = parser.parse_args()
    adb = MuMu().connect(args.instance)
    package = 'io.github.kernelsuemulator.probe'
    adb.shell('am force-stop ' + package)
    adb.shell('am start -W -n ' + package + '/.ProbeActivity')
    time.sleep(3)
    pid = int(adb.shell('pidof ' + package))
    session = bounded(frida.get_device(adb.serial, timeout=5).attach, pid)
    source = (Path(frida_tools.__file__).parent / 'bridges/java.js').read_text() + '\nglobalThis.Java=bridge;\n'
    source += '\n'.join((ROOT / 'scripts' / p).read_text() for p in
                       ('frida-android-init.js', 'frida-find.js', 'frida-tls-capture.js'))
    source += '''
      rpc.exports={async run(){
        const native=findNative('exports:libc.so!getpid');
        const modules=findModules('libc.so');
        const java=await findJava('java.lang.System!getProperty');
        const http=await new Promise((resolve,reject)=>Java.perform(()=>{
          try {const connection=Java.use('java.net.URL').$new('https://example.com/?ksu-frida-qa=1').openConnection();
            connection.setConnectTimeout(10000);connection.setReadTimeout(10000);
            connection.setRequestProperty('X-KSU-Frida-Qualification','controlled-diagnostic');
            connection.setRequestProperty('Accept-Encoding','identity');
            const stream=connection.getInputStream();let count=0;
            while(stream.read()!==-1)count++;stream.close();resolve(count);
          }catch(e){reject(e)}
        }));return {modules:modules.length,native:native.length,java:java.length,httpBytes:http};
      }};
    '''
    script = bounded(session.create_script, source)
    payloads, events, errors = [], [], []
    def message(value, data):
        if value.get('type') == 'error':
            errors.append(value)
        elif value.get('type') == 'send':
            events.append(value['payload'])
            if data:
                payloads.append(bytes(data))
    script.on('message', message)
    result = {'package': package, 'pid': pid, 'client': frida.__version__}
    try:
        bounded(script.load)
        result['helpers'] = bounded(script.exports_sync.run, timeout=40)
        time.sleep(1)
        data = b''.join(payloads)
        result['tls'] = {'events': len(payloads), 'bytes': len(data),
                         'sha256': hashlib.sha256(data).hexdigest(),
                         'request_seen': b'controlled-diagnostic' in data,
                         'response_seen': b'Example Domain' in data,
                         'providers': sorted({e.get('provider', '') for e in events if e.get('event') == 'tls-plaintext'})}
        result['errors'] = errors
        result['passed'] = all(result['helpers'][k] > 0 for k in ('modules', 'native', 'java', 'httpBytes')) and result['tls']['request_seen'] and result['tls']['response_seen'] and not errors
    finally:
        bounded(script.unload)
        bounded(session.detach)
        adb.shell('am force-stop ' + package)
        save_json(ROOT / 'out/audit/frida-helpers.json', result)
    print(result)
    return 0 if result.get('passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
