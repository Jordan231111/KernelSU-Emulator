#!/usr/bin/env python3
"""Exercise workers, child gating, Java stacks and session resumption in one app."""
import argparse
import hashlib
import json
import re
import shlex
import select
import socket
import socketserver
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path

import frida
import frida_tools

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from ksu_emulator.common import ROOT, save_json
from ksu_emulator.mumu import MuMu
from qualify_frida import bounded, wait_for


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--instance', required=True, type=int)
    parser.add_argument('--package', required=True)
    parser.add_argument('--case', choices=('all', 'child_gating', 'native_child_gating'), default='all')
    parser.add_argument('--runtime', choices=('qjs', 'v8'), default='qjs')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]+', args.package):
        parser.error('Invalid package')
    adb = MuMu().connect(args.instance)
    device = frida.get_device(adb.serial, timeout=5)
    pid = int(adb.shell('pidof ' + args.package).split()[0])
    output = ROOT / 'out/audit' / ('frida-extra-' + args.package + '.json')
    report = {'package': args.package, 'pid': pid, 'client': frida.__version__, 'cases': {}}
    bridge = (Path(frida_tools.__file__).parent / 'bridges/java.js').read_text()
    report['bridge_sha256'] = hashlib.sha256(bridge.encode()).hexdigest()
    report['child_runtime'] = args.runtime
    report['build_hashes'] = adb.su('sha256sum /system/etc/ksu-emulator/kernelsu.ko /data/adb/modules/mumu_susfs/susfs_guard_lkm.ko /data/local/tmp/uf-server')

    def case(name, expected, function):
        if args.case != 'all' and args.case != name:
            return
        try:
            report['cases'][name] = {'expected': expected, 'observed': function(), 'passed': True}
            print('PASS', name, flush=True)
        except Exception as error:
            report['cases'][name] = {'expected': expected, 'observed': str(error), 'exception': type(error).__name__, 'traceback': traceback.format_exc(), 'passed': False}
            print('FAIL', name, str(error), flush=True)
        save_json(output, report)

    def script_call(source, method='run'):
        session = bounded(device.attach, pid)
        script = bounded(session.create_script, source)
        errors = []
        script.on('message', lambda m, d: errors.append(m) if m.get('type') == 'error' else None)
        try:
            bounded(script.load)
            value = bounded(getattr(script.exports_sync, method))
            assert not errors, errors
            return value
        finally:
            bounded(script.unload)
            bounded(session.detach)

    def worker():
        # Keep the worker as its own ES module. Flattening/tree shaking an
        # import.meta.url worker into the entrypoint drops its run() export.
        modules = [(name, Path(__file__).with_name(name).read_text()) for name in
                   ('frida_worker_main.js', 'frida_worker.js')]
        source = '\U0001f4e6\n' + ''.join(str(len(body.encode())) + ' /' + name + '\n'
                                         for name, body in modules)
        source += '\u2704\n' + '\n\u2704\n'.join(body for name, body in modules)
        return script_call(source)
    case('javascript_worker', 'Separate JavaScript worker returns 42 through RPC and terminates', worker)

    def java_stack():
        return script_call(bridge + '''
          rpc.exports={run(){return new Promise((resolve,reject)=>bridge.perform(()=>{
            const Runnable=bridge.use('java.lang.Runnable');
            const Q=bridge.registerClass({name:'io.github.kernelsuemulator.frida.Stack'+Date.now(),
              implements:[Runnable],methods:{run(){
                try {const frames=bridge.backtrace().frames;
                  if(!frames.length) throw new Error('No Java stack frames');
                  resolve(frames.map(f=>({className:f.className,methodName:f.methodName})));}
                catch(e){reject(e)}
              }}});
            bridge.use('java.lang.Thread').$new(Q.$new()).start();
          }));}};
        ''')
    case('java_backtrace', 'A real Java Thread callback has Java stack frames', java_stack)

    def child_gating():
        session = bounded(device.attach, pid)
        script = bounded(session.create_script, bridge + '''
          let path, Q;
          rpc.exports={prepare(bytes){return new Promise((resolve,reject)=>bridge.perform(()=>{
            try {bridge.deoptimizeEverything();
              const cache=String(bridge.use('android.app.ActivityThread').currentApplication().getCacheDir());
              path=cache+'/ksu-frida-child.dex';const f=new File(path,'wb');
              f.write(new Uint8Array(bytes).buffer);f.close();
              bridge.openClassFile(path).load();Q=bridge.use('io.github.kernelsuemulator.frida.FridaChild');
              Q.result.value=-100;Q.error.value='';Q.control.value='';
              resolve(true);}catch(e){reject(e)}
          }));},run(){return new Promise((resolve,reject)=>bridge.perform(()=>{
            try {bridge.use('java.lang.Thread').$new(Q.$new()).start();resolve(true)}catch(e){reject(e)}
          }));},status(){return new Promise(resolve=>bridge.perform(()=>resolve({result:Q.result.value,error:String(Q.error.value)})));},cleanup(){
            const unlink=new NativeFunction(Process.getModuleByName('libc.so').getExportByName('unlink'),'int',['pointer']);
            return unlink(Memory.allocUtf8String(path));
          }};
        ''', runtime=args.runtime)
        children = []
        resume_errors = []
        def on_child(child):
            children.append({'pid': child.pid, 'parent_pid': child.parent_pid, 'origin': child.origin})
            # Never block the event-dispatch thread on a synchronous RPC.
            def resume():
                try:
                    bounded(device.resume, child.pid, timeout=10)
                except Exception as error:
                    resume_errors.append(str(error))
            threading.Thread(target=resume, daemon=True).start()
        device.on('child-added', on_child)
        try:
            bounded(script.load)
            bounded(script.exports_sync.prepare, list((ROOT / 'out/guest-tests/frida-dex/classes.dex').read_bytes()))
            bounded(session.enable_child_gating)
            bounded(script.exports_sync.run, timeout=10)
            status = wait_for(lambda: (lambda s: s if s['result'] != -100 else None)(
                bounded(script.exports_sync.status, timeout=5)), timeout=20)
            assert status['result'] == 23 and children and not resume_errors, (status, children, resume_errors)
            return {'child_exit': status['result'], 'events': children, 'dex_load': True}
        finally:
            bounded(session.disable_child_gating)
            device.off('child-added', on_child)
            bounded(script.exports_sync.cleanup, timeout=5)
            bounded(script.unload)
            bounded(session.detach)
    case('child_gating', 'The app child is reported, resumed, and exits with its selected status', child_gating)

    def native_child_gating():
        nonlocal pid
        adb.shell('am force-stop ' + args.package)
        adb.shell('monkey -p ' + args.package + ' -c android.intent.category.LAUNCHER 1')
        time.sleep(4)
        pid = int(adb.shell('pidof ' + args.package).split()[0])
        prep = bounded(device.attach, pid)
        script = bounded(prep.create_script, bridge + '''
          rpc.exports={prepare(bytes,suffix){return new Promise((resolve,reject)=>bridge.perform(()=>{
            try {const cache=String(bridge.use('android.app.ActivityThread').currentApplication().getCacheDir());
              const dex=cache+'/ksu-frida-child.dex',base=cache+'/ksu-frida-child-'+suffix;
              const f=new File(dex,'wb');f.write(new Uint8Array(bytes).buffer);f.close();
              bridge.openClassFile(dex).load();const Q=bridge.use('io.github.kernelsuemulator.frida.FridaChild');
              const task=Q.$new();Q.control.value=base;
              const flag=new File(base+'.go','wb');flag.write('0');flag.close();
              bridge.use('java.lang.Thread').$new(task).start();resolve({base,dex});
            }catch(e){reject(e)}
          }));}};
        ''')
        bounded(script.load)
        paths = bounded(script.exports_sync.prepare,
            list((ROOT / 'out/guest-tests/frida-dex/classes.dex').read_bytes()), uuid.uuid4().hex)
        bounded(script.unload)
        bounded(prep.detach)
        gate = bounded(device.attach, pid)
        children, errors, jobs = [], [], []
        def on_child(child):
            def inspect():
                session = None
                try:
                    session = bounded(device.attach, child.pid, timeout=10)
                    js = bounded(session.create_script, 'rpc.exports={pid(){return Process.id;}};')
                    bounded(js.load)
                    assert bounded(js.exports_sync.pid) == child.pid
                    children.append({'pid': child.pid, 'origin': child.origin, 'native_rpc': True})
                    bounded(js.unload)
                except Exception as error:
                    errors.append(str(error))
                finally:
                    try:
                        bounded(device.resume, child.pid, timeout=10)
                    except Exception as error:
                        errors.append('resume: ' + str(error))
                    if session is not None:
                        try:
                            bounded(session.detach, timeout=5)
                        except frida.InvalidOperationError:
                            pass  # A resumed exit-only child may already be gone.
            job = threading.Thread(target=inspect, daemon=True)
            jobs.append(job)
            job.start()
        device.on('child-added', on_child)
        try:
            bounded(gate.enable_child_gating)
            adb.su('printf 1 > ' + shlex.quote(paths['base'] + '.go'))
            result = wait_for(lambda: adb.su('cat ' + shlex.quote(paths['base'] + '.result') + ' 2>/dev/null', check=False), timeout=25)
            for job in jobs:
                job.join(timeout=10)
            assert result == '23' and children and not errors, (result, children, errors)
            return {'child_exit': int(result), 'events': children,
                    'java_preparation_unloaded_before_fork': True, 'parent_pid': pid}
        finally:
            bounded(gate.disable_child_gating)
            bounded(gate.detach)
            device.off('child-added', on_child)
            adb.su('rm -f ' + ' '.join(shlex.quote(p) for p in
                (paths['dex'], paths['base'] + '.go', paths['base'] + '.result')), check=False)
    case('native_child_gating', 'Unload Java preparation, then gate and instrument the child through native RPC', native_child_gating)

    def session_resume():
        # This only closes this test's loopback transport. ADB and other sessions
        # are not disconnected; the target retains the explicitly persistent agent.
        port = int(adb.call('forward', 'tcp:0', 'tcp:27042').stdout.strip())
        connections = set()
        lock = threading.Lock()
        class Forward(socketserver.BaseRequestHandler):
            def handle(self):
                with socket.create_connection(('127.0.0.1', port)) as upstream:
                    pair = (self.request, upstream)
                    with lock:
                        connections.update(pair)
                    try:
                        while True:
                            ready, _, _ = select.select(pair, [], [], 1)
                            for source in ready:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (upstream if source is self.request else self.request).sendall(data)
                    except (OSError, ValueError):
                        pass
                    finally:
                        with lock:
                            connections.difference_update(pair)
        proxy = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Forward)
        proxy.daemon_threads = True
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        address = '127.0.0.1:' + str(proxy.server_address[1])
        manager = frida.get_device_manager()
        remote = manager.add_remote_device(address)
        session = bounded(remote.attach, pid, persist_timeout=30)
        script = bounded(session.create_script, 'let n=0;rpc.exports={next(){return ++n;}};')
        events = []
        session.on('detached', lambda reason, crash: events.append(reason))
        try:
            bounded(script.load)
            assert bounded(script.exports_sync.next) == 1
            with lock:
                for connection in tuple(connections):
                    connection.shutdown(socket.SHUT_RDWR)
            wait_for(lambda: events)
            bounded(session.resume, timeout=20)
            assert bounded(script.exports_sync.next) == 2
            return {'detached': events, 'state_preserved': True}
        finally:
            try:
                bounded(session.detach, timeout=5)
            finally:
                manager.remove_remote_device(address)
                proxy.shutdown()
                proxy.server_close()
                adb.call('forward', '--remove', 'tcp:' + str(port), check=False)
    case('persistent_session_resume', 'Transient transport loss preserves agent state after Session.resume', session_resume)
    report['target_alive'] = str(pid) in adb.shell('pidof ' + args.package, check=False).split()
    report['enforcing'] = adb.su('cat /sys/fs/selinux/enforce')
    report['passed'] = all(c['passed'] for c in report['cases'].values()) and report['target_alive'] and report['enforcing'] == '1'
    save_json(output, report)
    print(output)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
