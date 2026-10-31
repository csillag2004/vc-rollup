#!/usr/bin/env node
// Own one fresh Anvil process per run; never connect to a caller's existing chain.
import { spawn } from 'node:child_process';
import { mkdir, writeFile, appendFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [mode, ...args] = process.argv.slice(2);
if (!['evaluate', 'benchmark', 'robustness', 'reproduce', 'demo'].includes(mode) || args.some(a => a !== '--smoke')) {
  console.error('Usage: node scripts/run.mjs <evaluate|benchmark|robustness|reproduce|demo> [--smoke]');
  process.exit(2);
}
const out = resolve(process.env.OUT || resolve(root, 'out'));
await mkdir(out, { recursive: true });
const log = resolve(out, `anvil-${mode}.log`);
await writeFile(log, '');
const children = new Set();
let interrupted = false;
function launch(command, options) {
  const child = spawn(command, options.args, { cwd: root, ...options, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child);
  child.once('close', () => children.delete(child));
  return child;
}
// Each child owns a process group so cancellation also stops npm/test descendants.
function signalChild(child, signal) {
  try {
    if (process.platform === 'win32') child.kill(signal);
    else if (child.pid) process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}
async function stop(child) {
  if (!children.has(child)) return;
  await new Promise(resolveStop => {
    const timer = setTimeout(() => { signalChild(child, 'SIGKILL'); }, 3000);
    child.once('close', () => { clearTimeout(timer); resolveStop(); });
    signalChild(child, 'SIGTERM');
  });
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  interrupted = true;
  for (const child of children) signalChild(child, 'SIGTERM');
});
const anvil = launch('anvil', { args: ['--host', '127.0.0.1', '--port', '0', '--hardfork', 'prague', '--chain-id', '31337'] });
const record = [];
const captions = [];
const start = performance.now();
const elapsed = () => (performance.now() - start) / 1000;
let transcript = '';
function output(chunk, stderr = false) {
  const text = chunk.toString().replaceAll(root, '<repo>');
  (stderr ? process.stderr : process.stdout).write(text);
  record.push([elapsed(), 'o', text.replace(/\r?\n/g, '\r\n')]);
  transcript += text;
  for (const line of text.split(/\r?\n/).filter(Boolean)) captions.push([elapsed(), line]);
}
function timestamp(seconds) {
  return new Date(Math.max(0, seconds) * 1000).toISOString().slice(11, 23);
}
try {
  const rpc = await new Promise((resolveReady, reject) => {
    let buffer = '';
    let writes = Promise.resolve();
    const timer = setTimeout(() => reject(new Error(`Anvil startup timed out; see ${log}`)), 30000);
    const finish = fn => value => { clearTimeout(timer); fn(value); };
    anvil.once('error', finish(reject));
    anvil.once('exit', code => finish(reject)(new Error(`Anvil exited (${code}); see ${log}`)));
    for (const stream of [anvil.stdout, anvil.stderr]) stream.on('data', chunk => {
      writes = writes.then(() => appendFile(log, chunk)).catch(error => { console.error(error); });
      buffer += chunk.toString();
      const match = buffer.match(/Listening on 127\.0\.0\.1:(\d+)/);
      if (match) finish(resolveReady)(`http://127.0.0.1:${match[1]}`);
    });
  });
  if (interrupted) throw new Error('Interrupted');
  const probe = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }), signal: AbortSignal.timeout(5000) }).then(r => r.json());
  if (probe.result !== '0x7a69') throw new Error('Unexpected local chain ID');
  output(Buffer.from(`$ node offchain/eval/artifact.ts ${[mode, ...args].join(' ')}\nFresh local Prague chain: ${rpc}\n`));
  const child = launch(process.execPath, { args: ['offchain/eval/artifact.ts', mode, ...args], env: { ...process.env, RPC: rpc, ANVIL_RPC: rpc, TARGET: 'anvil', OUT: out } });
  child.stdout.on('data', data => output(data));
  child.stderr.on('data', data => output(data, true));
  const timeout = args.includes('--smoke') ? 600000 : 3600000;
  await new Promise((resolveRun, reject) => {
    const timer = setTimeout(() => { signalChild(child, 'SIGTERM'); reject(new Error(`Evaluation timed out after ${timeout / 1000}s`)); }, timeout);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (code === 0 && !interrupted) resolveRun();
      else reject(new Error(`Evaluation failed (exit ${code}, signal ${signal})`));
    });
  });
} catch (error) {
  output(Buffer.from(`${error.message}\n`), true);
  process.exitCode = 1;
} finally {
  await Promise.all([...children].map(stop));
  if (mode === 'demo') {
    const dest = resolve(out, 'demo');
    await mkdir(dest, { recursive: true });
    await writeFile(resolve(dest, 'demo.cast'), [JSON.stringify({ version: 2, width: 120, height: 35, timestamp: Math.floor(Date.now() / 1000), title: 'Credential registry local demo', env: { TERM: 'xterm-256color' } }), ...record.map(row => JSON.stringify(row))].join('\n') + '\n');
    await writeFile(resolve(dest, 'transcript.txt'), transcript);
    await writeFile(resolve(dest, 'captions.vtt'), 'WEBVTT\n\n' + captions.map(([time, text], i) => `${i + 1}\n${timestamp(time)} --> ${timestamp(Math.max(time + 0.01, captions[i + 1]?.[0] ?? time + 3))}\n${text.replaceAll('-->', '→')}\n`).join('\n'));
    console.log(`Recording: ${dest}/demo.cast`);
  }
}
