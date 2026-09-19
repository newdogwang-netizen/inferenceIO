#!/usr/bin/env node
// Real Chromium DOM checks. Print only aggregate checks, never recorded bodies.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const origin = new URL(process.argv[2] ?? 'http://127.0.0.1:8088');
assert(['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname) && origin.protocol === 'http:');
const parent = process.argv[3];
assert(parent, 'pass a qualified parent connection ID');
const profile = await mkdtemp(join(tmpdir(), 'iorec-evidence-ui-'));
const browser = spawn(process.env.IOREC_CHROME_BIN ?? '/opt/google/chrome/chrome', [
  '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update',
  // This throwaway, credential-free profile must not wait for an interactive
  // desktop secret-service/keyring before network requests can proceed.
  '--password-store=basic',
  '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
const exited = new Promise(resolve => browser.once('exit', resolve));
let socket;
const pending = new Map();
let nextID = 0;
let sessionId;
let runtimeErrors = 0;
const report = { passed: false, checks: {} };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

try {
  const wsURL = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Chrome startup timeout')), 15000);
    let stderr = '';
    browser.once('error', e => { clearTimeout(timer); reject(e); });
    browser.stderr.on('data', chunk => {
      stderr = (stderr + String(chunk)).slice(-4096);
      const match = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  socket = new WebSocket(wsURL);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = ({ data }) => {
    const value = JSON.parse(data);
    if (value.method === 'Runtime.exceptionThrown') runtimeErrors++;
    const entry = pending.get(value.id);
    if (entry) {
      pending.delete(value.id);
      clearTimeout(entry.timer);
      if (value.error) entry.reject(new Error('CDP command rejected'));
      else entry.resolve(value.result);
    }
  };
  const command = (method, params = {}, session = sessionId) => new Promise((resolve, reject) => {
    report.last_command = method;
    const id = ++nextID;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, ...(session ? { sessionId: session } : {}) }));
  });
  const target = await command('Target.createTarget', { url: new URL(`/attempts/${encodeURIComponent(parent)}`, origin).href });
  sessionId = (await command('Target.attachToTarget', { targetId: target.targetId, flatten: true })).sessionId;
  await command('Runtime.enable');
  const evaluate = async expression => {
    const r = await command('Runtime.evaluate', { expression, returnByValue: true });
    assert(!r.exceptionDetails, 'DOM evaluation failed');
    return r.result.value;
  };
  const waitFor = async expression => {
    for (let i = 0; i < 100; i++) { if (await evaluate(expression)) return; await delay(200); }
    report.dom_diagnostic = await evaluate(`({ready:document.readyState,title:document.title,headers:[...document.querySelectorAll('h2,h3')].map(x=>x.textContent),bodyLength:document.body?.textContent?.length,rootChildren:document.querySelector('#root')?.children.length})`);
    throw new Error('expected DOM state did not appear');
  };
  const click = label => evaluate(`[...document.querySelectorAll('button')].find(b=>b.textContent===${JSON.stringify(label)})?.click()`);
  await waitFor(`document.body.textContent.includes('逐次模型调用（19）')`);
  report.checks.parent_calls = await evaluate(`document.querySelectorAll('tbody tr').length`);
  assert.equal(report.checks.parent_calls, 19);
  report.checks.initial_dom_characters = await evaluate(`document.documentElement.outerHTML.length`);
  assert(report.checks.initial_dom_characters < 100000, 'parent detail eagerly renders raw evidence');
  await waitFor(`document.body.textContent.includes('reward 0')`);
  report.checks.benchmark_zero_reward_separate = true;
  const childURL = await evaluate(`[...document.querySelectorAll('tbody a')].find(a=>a.textContent==='调用 2')?.href`);
  assert(childURL?.startsWith(origin.origin), 'missing child link');
  await click('原始协议事件');
  await waitFor(`document.querySelectorAll('tbody tr').length===100`);
  const firstSeq = await evaluate(`document.querySelector('tbody tr td a').textContent`);
  await click('下一页');
  await waitFor(`document.querySelectorAll('tbody tr').length===100 && document.querySelector('tbody tr td a').textContent!==${JSON.stringify(firstSeq)}`);
  report.checks.event_pages = 2;
  report.checks.rows_per_page = 100;
  await click('传输证明');
  await waitFor(`document.body.textContent.includes('target-network-namespace-ip-transport')`);
  assert(await evaluate(`document.body.textContent.includes('verified') && document.body.textContent.includes('unknown') && document.body.textContent.includes('rustls-binary-marker')`));
  report.checks.proof_and_tls_boundary_visible = true;
  await evaluate(`location.href=${JSON.stringify(childURL)}`);
  await waitFor(`document.body.textContent.includes('查看连接') && document.body.textContent.includes('模型结果')`);
  await click('规范化内容');
  await waitFor(`document.body.textContent.includes('不替代原始证据')`);
  await click('响应文本 / 正文');
  await waitFor(`document.body.textContent.includes('不是全部响应正文') && document.body.textContent.includes('结束响应正文')`);
  report.checks.child_evidence_views = true;
  assert.equal(runtimeErrors, 0, 'browser runtime error');
  report.checks.runtime_errors = runtimeErrors;
  report.passed = true;
  await command('Browser.close', {}, null).catch(() => {});
} finally {
  socket?.close();
  for (const item of pending.values()) clearTimeout(item.timer);
  browser.kill('SIGTERM');
  await Promise.race([exited, delay(3000)]);
  if (browser.exitCode === null && browser.signalCode === null) { browser.kill('SIGKILL'); await exited; }
  // Exact directory created above; contains a private browser cache of evidence.
  await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  report.private_browser_profile_removed = true;
  report.runtime_errors = runtimeErrors;
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}
