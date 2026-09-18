#!/usr/bin/env node
// Synthetic protocol workload only: never calls a public provider.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';

const args = Object.fromEntries(process.argv.slice(2).reduce((out, value, index, all) => {
  if (index % 2 === 0) out.push([value.replace(/^--/, ''), all[index+1]]);
  return out;
}, []));
const endpoint = new URL(process.env[args['url-env'] ?? 'IOREC_PROXY_URL'] ?? '');
assert.equal(endpoint.protocol, 'http:');
assert(['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname), 'loopback fixture required');
assert(!endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash);
endpoint.protocol = 'ws:';
endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/v1/responses';
const duration = Number(args['duration-seconds']);
const interval = Number(args['interval-seconds']);
const perConnection = Number(args['calls-per-connection'] ?? 11);
assert(Number.isFinite(duration) && duration > 0 && duration <= 7*86400);
assert(Number.isFinite(interval) && interval > 0);
assert(Number.isInteger(perConnection) && perConnection >= 2 && perConnection <= 100);
assert(Math.ceil(duration/interval) <= 1000, 'bounded expected-call ledger exceeded');
const prefix = randomUUID();
const requestID = index => `q-${prefix}-${index}`;
const responseID = index => `resp-${requestID(index)}`;
const textFor = index => `fixture-${index}-`+'x'.repeat(index % 13 === 12 ? 32768 : 256)+' 中文🙂';
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const expected = [];
const start = performance.now();
const deadline = start+duration*1000;
let connection;
let connections = 0;
let errorCode;

async function connect() {
  const ws = new WebSocket(endpoint);
  const queue = [];
  let waiter, closed = false, closeCode;
  const closePromise = new Promise(resolve => ws.addEventListener('close', event => {
    closed = true; closeCode = event.code;
    waiter?.reject(new Error('unexpected_socket_close'));
    resolve(event.code);
  }, { once: true }));
  ws.addEventListener('error', () => waiter?.reject(new Error('websocket_error')));
  ws.addEventListener('message', event => {
    if (typeof event.data !== 'string' || event.data.length > 128*1024 || queue.length >= 128) {
      waiter?.reject(new Error('unexpected_fixture_message'));
      ws.close(1002);
      return;
    }
    let value;
    try { value = JSON.parse(event.data); } catch { waiter?.reject(new Error('invalid_fixture_json')); ws.close(1002); return; }
    if (waiter) waiter.resolve(value);
    else queue.push(value);
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { ws.close(); reject(new Error('websocket_open_timeout')); }, 15000);
    ws.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    ws.addEventListener('error', () => { clearTimeout(timer); reject(new Error('websocket_open_error')); }, { once: true });
  });
  connections++;
  return {
    ws,
    next: async () => {
      if (queue.length) return queue.shift();
      if (closed) throw new Error('websocket_already_closed');
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { waiter = undefined; reject(new Error('response_timeout')); }, 15000);
        waiter = {
          resolve: value => { clearTimeout(timer); waiter = undefined; resolve(value); },
          reject: error => { clearTimeout(timer); waiter = undefined; reject(error); },
        };
      });
    },
    close: async () => {
      if (!closed) ws.close(1000);
      let timer;
      try {
        const code = await Promise.race([closePromise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('close_timeout')), 15000); })]);
        assert.equal(code, 1000, 'unclean_fixture_close');
        assert.equal(queue.length, 0, 'unconsumed_fixture_messages');
      } finally { clearTimeout(timer); }
      return closeCode;
    },
  };
}

try {
  for (let index = 0; index < Math.ceil(duration/interval) && performance.now() < deadline; index++) {
    if (!connection) connection = await connect();
    const id = requestID(index);
    const input = index % 2 ? [{ type: 'custom_tool_call_output', call_id: 'tool-'+requestID(index-1), output: `fixture-result-${index-1}` }]
      : [{ role: 'user', content: `fixture turn ${index}` }];
    const request = { type: 'response.create', event_id: id, model: 'fixture-ws-model', input,
      metadata: { fixture_index: index }, ...(index ? { previous_response_id: responseID(index-1) } : {}) };
    connection.ws.send(JSON.stringify(request));
    const created = await connection.next();
    assert(created.type === 'response.created' && created.request_id === id && created.response.id === responseID(index), 'created_event_mismatch');
    let text = '', toolDone = 0, events = 1;
    while (true) {
      const event = await connection.next();
      events++;
      if (event.type === 'response.output_text.delta') {
        assert.equal(event.response_id, responseID(index), 'delta_owner_mismatch');
        text += event.delta;
      } else if (event.type === 'response.output_item.done') {
        assert.equal(event.response_id, responseID(index));
        assert.equal(event.item.call_id, 'tool-'+id);
        toolDone++;
      } else {
        assert.equal(event.type, 'response.completed');
        const response = event.response;
        assert.equal(response.id, responseID(index));
        assert.equal(response.status, 'completed');
        assert.equal(response.model, 'fixture-ws-model');
        assert.equal(text, textFor(index), 'delta_content_mismatch');
        assert.equal(response.output[0].content[0].text, textFor(index), 'final_content_mismatch');
        assert.equal(toolDone, index % 2 ? 0 : 1, 'tool_snapshot_count');
        assert.equal(response.output.length, index % 2 ? 1 : 2);
        if (index % 2 === 0) {
          assert.deepEqual(response.output[1], { type: 'custom_tool_call', id: 'item-'+id,
            call_id: 'tool-'+id, name: 'fixture_exec', input: `printf turn ${index}` });
        }
        assert.equal(response.usage.input_tokens, 100+index);
        assert.equal(response.usage.output_tokens, 10+index % 7);
        expected.push({ index, request_id: id, response_id: responseID(index), previous_response_id: index ? responseID(index-1) : null,
          request_sha256: hash(JSON.stringify(canonical(request))),
          response_sha256: hash(JSON.stringify(canonical(response))),
          input_tokens: 100+index, output_tokens: 10+index % 7, response_text_sha256: hash(textFor(index)),
          tools: index % 2 ? 0 : 1, tool_results: index % 2 ? 1 : 0, server_messages: events });
        break;
      }
    }
    if ((index+1) % perConnection === 0) { await connection.close(); connection = undefined; }
    const next = Math.min(deadline, start+(index+1)*interval*1000);
    await delay(Math.max(0, next-performance.now()));
  }
  // Timers can fire slightly early. Meet the measured duration without sending
  // an extra request beyond the bounded ledger's planned call count.
  while (performance.now() < deadline) await delay(Math.max(1, deadline-performance.now()));
  if (connection) { await connection.close(); connection = undefined; }
} catch (error) {
  // Assert actual/expected values may contain protocol bodies. Emit only codes.
  errorCode = error?.code === 'ERR_ASSERTION' ? 'fixture_assertion_failed' : 'fixture_transport_failed';
  connection?.ws.close();
}
console.log(JSON.stringify({ workload: 'responses_websocket', requests: expected.length+(errorCode ? 1 : 0),
  successes: expected.length, errors: errorCode ? 1 : 0, error_samples: errorCode ? [errorCode] : [],
  transport_attempts: connections, measurement_seconds: (performance.now()-start)/1000, expected_calls: expected }));
if (errorCode) process.exitCode = 1;
