// SPDX-License-Identifier: MIT
import {url} from './frida_worker.js';
rpc.exports = {async run() {
  send({phase: 'worker-start', url});
  const worker = new Worker(url, {onMessage(message) { send({worker: message}); }});
  try {
    const answer = await worker.exports.add(19, 23);
    if (answer !== 42) throw new Error('Worker RPC mismatch');
    return {answer, terminated: true};
  } catch (error) { throw new Error('Worker RPC: ' + String(error) + ' ' + error?.stack); }
  finally { worker.terminate(); }
}};
