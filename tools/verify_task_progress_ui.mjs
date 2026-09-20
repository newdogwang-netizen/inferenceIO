#!/usr/bin/env node
// Real Chromium DOM checks. Print only aggregate checks, never recorded bodies.
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const origin = new URL(process.argv[2] ?? 'http://127.0.0.1:8088');
assert(['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname) && origin.protocol === 'http:');
const run = process.argv[3];
assert(run, 'pass a capture run ID');
const expectedCalls = Number(process.argv[4]);
const expectedTools = Number(process.argv[5]);
assert(Number.isInteger(expectedCalls) && expectedCalls > 0 && Number.isInteger(expectedTools));
const captureScreenshots = process.argv.includes('--screenshots');
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
  const target = await command('Target.createTarget', { url: new URL(`/recordings/${encodeURIComponent(run+'#0000')}`, origin).href });
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
  await command('Emulation.setDeviceMetricsOverride', {width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await waitFor("document.querySelectorAll('.activity-metrics dt').length===5");
  const metrics = await evaluate("[...document.querySelectorAll('.activity-metrics > div')].map(x=>({label:x.querySelector('dt').textContent,value:x.querySelector('dd').textContent}))");
  assert.deepEqual(metrics.map(x=>x.label), ['模型调用','工具执行','连接','Hook 观测','流式事件']);
  assert.equal(Number(metrics[0].value.replaceAll(',','')), expectedCalls);
  assert.equal(Number(metrics[1].value.split('/')[0].trim().replaceAll(',','')), expectedTools);
  report.checks.separate_metrics = metrics;
  assert.equal(await evaluate("document.querySelectorAll('.progress-step').length"), Math.min(expectedCalls,25));
  report.checks.first_page_steps = Math.min(expectedCalls,25);
  assert(await evaluate("document.body.textContent.includes('不把时间先后当作因果关系')"));
  assert(await evaluate("[...document.querySelectorAll('.progress-step a')].some(a=>a.textContent==='调用详情')"));
  assert(await evaluate("[...document.querySelectorAll('.progress-step a')].some(a=>a.textContent.startsWith('原始 seq'))"));
  report.checks.causality_and_evidence_links = true;
  if (expectedTools > 0) {
    await evaluate("document.querySelector('.progress-tool').open=true");
    assert(await evaluate("document.body.textContent.includes('工具请求证据') && document.body.textContent.includes('首次观察到结果的调用')"));
    report.checks.tool_operation_and_result_expand = true;
  }
  if (expectedCalls > 25) {
    await click('下一页');
    await waitFor("document.querySelector('.progress-step-title strong')?.textContent==='调用 26'");
    await click('上一页');
    await waitFor("document.querySelector('.progress-step-title strong')?.textContent==='调用 1'");
    report.checks.progress_pagination = true;
  }
  if (captureScreenshots) {
    report.screenshot_directory = await mkdtemp(join(tmpdir(), 'iorec-progress-view-'));
    const shot = await command('Page.captureScreenshot', {format:'png'});
    await writeFile(join(report.screenshot_directory,'desktop.png'),Buffer.from(shot.data,'base64'),{mode:0o600});
  }
  assert(await evaluate("document.documentElement.scrollWidth<=window.innerWidth"),'desktop overflow');
  await command('Emulation.setDeviceMetricsOverride', {width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert(await evaluate("document.documentElement.scrollWidth<=window.innerWidth"),'mobile overflow');
  report.checks.mobile_no_horizontal_overflow = true;
  if (captureScreenshots) {
    const shot = await command('Page.captureScreenshot', {format:'png'});
    await writeFile(join(report.screenshot_directory,'mobile.png'),Buffer.from(shot.data,'base64'),{mode:0o600});
  }
  await command('Emulation.setDeviceMetricsOverride', {width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await evaluate("location.href="+JSON.stringify(new URL('/recordings',origin).href));
  await waitFor("document.querySelectorAll('tbody tr').length>0");
  const headers = await evaluate("[...document.querySelectorAll('th')].map(x=>x.textContent)");
  for (const label of ['模型调用','工具执行','连接（WS）','Hook 观测','流式事件']) assert(headers.includes(label));
  assert(!headers.includes('attempt'));
  report.checks.recording_list_separate_columns = true;
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
