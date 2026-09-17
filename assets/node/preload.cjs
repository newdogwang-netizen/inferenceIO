/* Fail-open iorec instrumentation for Node.js model and HTTP clients.
 *
 * This file is embedded in the Rust binary and materialized in a private run
 * directory. It intentionally uses only Node.js built-ins.
 */
'use strict';

const Module = require('node:module');
const net = require('node:net');
const { pathToFileURL } = require('node:url');
const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { threadId, isMainThread, isInternalThread } = require('node:worker_threads');

const ENABLED = process.env.IOREC_NODE_INJECTION === '1' && isInternalThread !== true;
const SOCKET = process.env.IOREC_COLLECTOR_SOCKET;
const TOKEN = process.env.IOREC_COLLECTOR_TOKEN;
const QUEUE_LIMIT = 256;
const MAX_DEPTH = 24;
const MAX_ITEMS = 10_000;
const MAX_BINARY_BYTES = 1 << 20;
const MAX_STRING_BYTES = 1 << 20;
const MAX_RECORD_BYTES = 4 << 20;
const MAX_STREAM_BYTES = 64 << 20;
const MAX_STREAM_CHUNKS = 100_000;
const SOCKET_TIMEOUT_MS = 500;
const NO_PROGRESS_DEADLINE_MS = 1_000;
const PATCH_VERSION = 1;
const SENSITIVE_KEYS = new Set([
  'authorization', 'api-key', 'cookie', 'set-cookie', 'password',
  'proxy-authorization', 'access-token', 'auth-token', 'refresh-token',
  'client-secret', 'secret', 'token', 'x-api-key',
]);

const queue = [];
const inferenceContext = new AsyncLocalStorage();
const wrappedConstructors = new WeakMap();
const wrappedModules = new WeakMap();
let sending = false;
let drops = 0;

function sensitiveKey(value) {
  return SENSITIVE_KEYS.has(String(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .toLowerCase()
    .replaceAll('_', '-'));
}

function boundedString(value, state) {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length <= MAX_STRING_BYTES) return value;
  state.truncated = true;
  return {
    text: bytes.subarray(0, MAX_STRING_BYTES).toString('utf8'),
    _iorec_truncated: true,
  };
}

function sanitize(value, state = undefined, depth = 0) {
  state ||= { items: 0, truncated: false, seen: new WeakSet() };
  if (depth > MAX_DEPTH || state.items >= MAX_ITEMS) {
    state.truncated = true;
    return { _iorec_omitted: 'complexity_limit' };
  }
  state.items += 1;
  if (value === null || value === undefined || typeof value === 'boolean' ||
      typeof value === 'number' || typeof value === 'string') {
    return typeof value === 'string' ? boundedString(value, state) : value;
  }
  if (typeof value === 'bigint') return value.toString(10);
  if (typeof value === 'symbol' || typeof value === 'function') {
    return { _iorec_type: typeof value };
  }
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    const bytes = Buffer.isBuffer(value)
      ? value
      : value instanceof ArrayBuffer
        ? Buffer.from(value)
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    const kept = bytes.subarray(0, MAX_BINARY_BYTES);
    state.truncated ||= kept.length !== bytes.length;
    return {
      _iorec_binary_base64: kept.toString('base64'),
      _iorec_original_bytes: bytes.length,
      _iorec_truncated: kept.length !== bytes.length,
    };
  }
  if (state.seen.has(value)) {
    state.truncated = true;
    return { _iorec_omitted: 'cycle' };
  }
  state.seen.add(value);
  try {
    if (value instanceof URL) return value.toString();
    if (typeof Headers !== 'undefined' && value instanceof Headers) {
      const headers = {};
      for (const [key, item] of value.entries()) {
        headers[key] = sensitiveKey(key) ? '[REDACTED]' : boundedString(item, state);
      }
      return headers;
    }
    const output = Array.isArray(value) ? [] : {};
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (state.items >= MAX_ITEMS) {
        state.truncated = true;
        break;
      }
      if (typeof key !== 'string') continue;
      const descriptor = descriptors[key];
      if (!Object.hasOwn(descriptor, 'value')) {
        output[key] = { _iorec_omitted: 'accessor' };
      } else {
        output[key] = sensitiveKey(key)
          ? '[REDACTED]'
          : sanitize(descriptor.value, state, depth + 1);
      }
    }
    if (!Array.isArray(value) && value.constructor && value.constructor !== Object) {
      output._iorec_type = value.constructor.name || 'Object';
    }
    return output;
  } catch (error) {
    state.truncated = true;
    return {
      _iorec_type: value?.constructor?.name || 'Object',
      _iorec_omitted: 'conversion_error',
    };
  } finally {
    state.seen.delete(value);
  }
}

function submission(event, payload, inferenceId = undefined, terminalState = undefined) {
  const state = { items: 0, truncated: false, seen: new WeakSet() };
  let safe = sanitize(payload, state);
  if (!safe || typeof safe !== 'object' || Array.isArray(safe)) safe = { value: safe };
  if (state.truncated) safe._iorec_capture_truncated = true;
  safe._iorec_runtime_pid = process.pid;
  safe._iorec_runtime_thread_id = threadId;
  const message = {
    token: TOKEN,
    source: 'node-runtime',
    event,
    payload: safe,
    ids: inferenceId ? { inference_id: inferenceId } : {},
    confidence: 1.0,
    evidence: ['runtime_injection', 'node_runtime'],
  };
  if (terminalState) message.terminal_state = terminalState;
  return { message, truncated: state.truncated };
}

function encode(event, payload, inferenceId = undefined, terminalState = undefined) {
  let { message, truncated } = submission(event, payload, inferenceId, terminalState);
  let encoded = Buffer.from(JSON.stringify(message));
  if (encoded.length > MAX_RECORD_BYTES) {
    ({ message } = submission(event, {
      _iorec_omitted: 'record_size_limit',
      encoded_bytes: encoded.length,
    }, inferenceId, terminalState));
    encoded = Buffer.from(JSON.stringify(message));
    truncated = true;
  }
  return { encoded, truncated };
}

function noteDrop(count = 1) {
  drops += Math.max(1, Number.isSafeInteger(count) ? count : 1);
}

function enqueue(event, payload, inferenceId = undefined, terminalState = undefined) {
  if (!ENABLED || !SOCKET || !TOKEN) return;
  try {
    const { encoded, truncated } = encode(event, payload, inferenceId, terminalState);
    if (queue.length >= QUEUE_LIMIT) {
      noteDrop();
      return;
    }
    queue.push(encoded);
    if (truncated) noteDrop();
    drain();
  } catch (_) {
    noteDrop();
  }
}

function send(encoded) {
  return new Promise((resolve) => {
    let settled = false;
    let response = Buffer.alloc(0);
    const socket = net.createConnection({ path: SOCKET });
    const finish = (accepted) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(accepted);
    };
    socket.setTimeout(SOCKET_TIMEOUT_MS, () => finish(false));
    socket.on('connect', () => socket.end(encoded));
    socket.on('data', (chunk) => {
      if (response.length < 4096) response = Buffer.concat([response, chunk]).subarray(0, 4096);
    });
    socket.on('end', () => {
      try {
        finish(JSON.parse(response.toString('utf8')).accepted === true);
      } catch (_) {
        finish(false);
      }
    });
    socket.on('error', () => finish(false));
  });
}

async function drain() {
  if (sending) return;
  sending = true;
  let deadline = Date.now() + NO_PROGRESS_DEADLINE_MS;
  try {
    while (queue.length > 0) {
      if (Date.now() >= deadline) {
        noteDrop(queue.length);
        queue.length = 0;
        const omitted = drops;
        drops = 0;
        const gap = encode('runtime_capture_gap', {
          reason: 'runtime_sender_deadline', occurrences: omitted,
        }, undefined, 'incomplete').encoded;
        if (!await send(gap)) drops += omitted;
        break;
      }
      const pendingDrops = drops;
      drops = 0;
      if (pendingDrops > 0) {
        const gap = encode('runtime_capture_gap', {
          reason: 'runtime_queue_or_submission_loss',
          occurrences: pendingDrops,
        }, undefined, 'incomplete').encoded;
        if (await send(gap)) deadline = Date.now() + NO_PROGRESS_DEADLINE_MS;
        else drops += pendingDrops;
      }
      const encoded = queue.shift();
      if (await send(encoded)) deadline = Date.now() + NO_PROGRESS_DEADLINE_MS;
      else noteDrop();
    }
  } catch (_) {
    noteDrop();
  } finally {
    if (drops > 0 && Date.now() < deadline) {
      const pending = drops;
      drops = 0;
      try {
        const gap = encode('runtime_capture_gap', {
          reason: 'runtime_queue_or_submission_loss', occurrences: pending,
        }, undefined, 'incomplete').encoded;
        if (!await send(gap)) drops += pending;
      } catch (_) {
        drops += pending;
      }
    }
    sending = false;
    if (queue.length > 0) setImmediate(drain);
  }
}

function errorType(error) {
  return error?.constructor?.name || typeof error;
}

function patchIteratorNext(value, inferenceId, api, lifecycle) {
  if (!value || typeof value.next !== 'function') return false;
  if (value.__iorecIteratorWrapped) return true;
  try {
    const originalNext = value.next;
    Object.defineProperty(value, '__iorecIteratorWrapped', { value: true });
    Object.defineProperty(value, 'next', {
      configurable: true,
      writable: true,
      value: function (...args) {
        let result;
        try {
          result = originalNext.apply(this, args);
        } catch (error) {
          if (!lifecycle.terminal) {
            lifecycle.terminal = true;
            enqueue('model_stream_error', { api, error_type: errorType(error) }, inferenceId, 'error');
          }
          throw error;
        }
        if (!result || typeof result.then !== 'function') {
          if (result?.done) {
            if (!lifecycle.terminal) {
              lifecycle.terminal = true;
              enqueue('model_stream_completed', { api }, inferenceId, 'complete');
            }
          } else enqueue('model_stream_event', { api, chunk: result?.value }, inferenceId);
          return result;
        }
        return result.then(
          (item) => {
            if (item?.done) {
              if (!lifecycle.terminal) {
                lifecycle.terminal = true;
                enqueue('model_stream_completed', { api }, inferenceId, 'complete');
              }
            } else enqueue('model_stream_event', { api, chunk: item?.value }, inferenceId);
            return item;
          },
          (error) => {
            if (!lifecycle.terminal) {
              lifecycle.terminal = true;
              enqueue('model_stream_error', { api, error_type: errorType(error) }, inferenceId, 'error');
            }
            throw error;
          },
        );
      },
    });
    if (typeof value.return === 'function') {
      const originalReturn = value.return;
      Object.defineProperty(value, 'return', {
        configurable: true,
        writable: true,
        value: function (...args) {
          const cancelled = () => {
            if (!lifecycle.terminal) {
              lifecycle.terminal = true;
              enqueue('model_stream_cancelled', { api }, inferenceId, 'incomplete');
            }
          };
          let result;
          try { result = originalReturn.apply(this, args); } catch (error) {
            cancelled();
            throw error;
          }
          if (!result || typeof result.then !== 'function') {
            cancelled();
            return result;
          }
          return result.then(
            (item) => { cancelled(); return item; },
            (error) => { cancelled(); throw error; },
          );
        },
      });
    }
    return true;
  } catch (_) {
    return false;
  }
}

function observeAsyncIterator(value, inferenceId, api) {
  if (!value || value.__iorecStreamWrapped) return value?.__iorecStreamWrapped === true;
  const lifecycle = { terminal: false };
  try {
    Object.defineProperty(value, '__iorecStreamWrapped', { value: true });
    let wrapped = patchIteratorNext(value, inferenceId, api, lifecycle);
    if (!wrapped && typeof value[Symbol.asyncIterator] === 'function') {
      const originalIterator = value[Symbol.asyncIterator];
      Object.defineProperty(value, Symbol.asyncIterator, {
        configurable: true,
        writable: true,
        value: function (...args) {
          const iterator = originalIterator.apply(this, args);
          if (!patchIteratorNext(iterator, inferenceId, api, lifecycle)) {
            enqueue('runtime_capture_gap', {
              reason: 'stream_iterator_rejected_correlation', occurrences: 1,
            }, inferenceId, 'incomplete');
          }
          return iterator;
        },
      });
      wrapped = true;
    }
    if (!wrapped) throw new Error('unsupported stream iterator');
    enqueue('model_stream_started', { api }, inferenceId);
    return true;
  } catch (_) {
    enqueue('runtime_capture_gap', {
      reason: 'stream_object_rejected_correlation', occurrences: 1,
    }, inferenceId, 'incomplete');
    return false;
  }
}

function observeModelResult(value, inferenceId, api) {
  if (!observeAsyncIterator(value, inferenceId, api)) {
    enqueue('model_call_completed', { api, response: value }, inferenceId, 'complete');
  }
  return value;
}

function observeThenable(value, inferenceId, api) {
  if (!value || typeof value.then !== 'function') return observeModelResult(value, inferenceId, api);
  if (value.__iorecThenWrapped) return value;
  try {
    const originalThen = value.then;
    Object.defineProperty(value, '__iorecThenWrapped', { value: true });
    Object.defineProperty(value, 'then', {
      configurable: true,
      writable: true,
      value: function (onFulfilled, onRejected) {
        return inferenceContext.run(inferenceId, () => originalThen.call(
          this,
          (result) => {
            observeModelResult(result, inferenceId, api);
            return typeof onFulfilled === 'function' ? onFulfilled(result) : result;
          },
          (error) => {
            enqueue('model_call_error', { api, error_type: errorType(error) }, inferenceId, 'error');
            if (typeof onRejected === 'function') return onRejected(error);
            throw error;
          },
        ));
      },
    });
  } catch (_) {
    enqueue('runtime_capture_gap', {
      reason: 'model_promise_rejected_observer', occurrences: 1,
    }, inferenceId, 'incomplete');
  }
  return value;
}

function wrapCreate(resource, api) {
  if (!resource || typeof resource.create !== 'function' || resource.create.__iorecWrapped) return;
  const original = resource.create;
  const wrapped = function (...args) {
    const inferenceId = randomUUID();
    enqueue('model_call_started', { api, args }, inferenceId);
    try {
      return inferenceContext.run(inferenceId, () => observeThenable(
        original.apply(this, args), inferenceId, api,
      ));
    } catch (error) {
      enqueue('model_call_error', { api, error_type: errorType(error) }, inferenceId, 'error');
      throw error;
    }
  };
  Object.defineProperty(wrapped, '__iorecWrapped', { value: true });
  try { resource.create = wrapped; } catch (_) {
    enqueue('runtime_capture_gap', { reason: 'model_resource_patch_failed', occurrences: 1 }, undefined, 'incomplete');
  }
}

function wrapOpenAIClient(client) {
  try {
    wrapCreate(client?.chat?.completions, 'chat.completions');
    wrapCreate(client?.responses, 'responses');
  } catch (_) {
    enqueue('runtime_capture_gap', { reason: 'model_client_patch_failed', occurrences: 1 }, undefined, 'incomplete');
  }
  return client;
}

function wrapConstructor(ctor) {
  if (typeof ctor !== 'function') return ctor;
  if (wrappedConstructors.has(ctor)) return wrappedConstructors.get(ctor);
  const proxy = new Proxy(ctor, {
    construct(target, args, newTarget) {
      return wrapOpenAIClient(Reflect.construct(target, args, newTarget));
    },
    apply(target, thisArg, args) {
      return wrapOpenAIClient(Reflect.apply(target, thisArg, args));
    },
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return (property === 'default' || property === 'OpenAI') && typeof value === 'function'
        ? wrapConstructor(value)
        : value;
    },
  });
  wrappedConstructors.set(ctor, proxy);
  return proxy;
}

function wrapOpenAIModule(exports) {
  if ((typeof exports !== 'object' || exports === null) && typeof exports !== 'function') return exports;
  if (wrappedModules.has(exports)) return wrappedModules.get(exports);
  const wrapped = typeof exports === 'function' ? wrapConstructor(exports) : new Proxy(exports, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return (property === 'default' || property === 'OpenAI') && typeof value === 'function'
        ? wrapConstructor(value)
        : value;
    },
  });
  wrappedModules.set(exports, wrapped);
  return wrapped;
}

function wrapPromiseCall(original, api) {
  if (typeof original !== 'function' || original.__iorecWrapped) return original;
  const wrapped = function (...args) {
    const requestId = randomUUID();
    const parentInferenceId = inferenceContext.getStore();
    enqueue('runtime_http_request_started', { api, args, parent_inference_id: parentInferenceId }, requestId);
    let result;
    try { result = original.apply(this, args); } catch (error) {
      enqueue('runtime_http_request_error', { api, error_type: errorType(error) }, requestId, 'error');
      throw error;
    }
    if (!result || typeof result.then !== 'function') {
      enqueue('runtime_http_request_completed', { api, result }, requestId, 'complete');
      return result;
    }
    return result.then(
      (response) => {
        enqueue('runtime_http_request_completed', {
          api,
          status: response?.status ?? response?.statusCode,
          headers: response?.headers,
        }, requestId, 'complete');
        observeResponseBody(response, requestId, api);
        return response;
      },
      (error) => {
        enqueue('runtime_http_request_error', { api, error_type: errorType(error) }, requestId, 'error');
        throw error;
      },
    );
  };
  Object.defineProperty(wrapped, '__iorecWrapped', { value: true });
  return wrapped;
}

async function observeResponseBody(response, requestId, api) {
  let clone;
  try {
    if (!response || typeof response.clone !== 'function') return;
    clone = response.clone();
    if (!clone.body || typeof clone.body.getReader !== 'function') return;
    const reader = clone.body.getReader();
    let bytes = 0;
    let chunks = 0;
    while (chunks < MAX_STREAM_CHUNKS && bytes < MAX_STREAM_BYTES) {
      const item = await reader.read();
      if (item.done) {
        enqueue('runtime_http_response_body_completed', { api, chunks, bytes }, requestId, 'complete');
        return;
      }
      const chunk = Buffer.from(item.value);
      chunks += 1;
      bytes += chunk.length;
      enqueue('runtime_http_response_body_chunk', { api, chunk }, requestId);
    }
    await reader.cancel('iorec capture limit');
    enqueue('runtime_capture_gap', {
      reason: 'http_response_stream_limit', occurrences: 1, chunks, bytes,
    }, requestId, 'incomplete');
  } catch (_) {
    enqueue('runtime_capture_gap', {
      reason: 'http_response_clone_failed', occurrences: 1,
    }, requestId, 'incomplete');
  }
}

function wrapUndiciModule(exports) {
  if (!exports || typeof exports !== 'object') return exports;
  if (wrappedModules.has(exports)) return wrappedModules.get(exports);
  const proxy = new Proxy(exports, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return ['fetch', 'request', 'stream'].includes(property)
        ? wrapPromiseCall(value, `undici.${property}`)
        : value;
    },
  });
  wrappedModules.set(exports, proxy);
  return proxy;
}

if (ENABLED && SOCKET && TOKEN) {
  globalThis[Symbol.for('iorec.node.runtime.v1')] = Object.freeze({
    wrapOpenAIConstructor: wrapConstructor,
  });
  let esmLoaderRegistered = false;
  try {
    if (typeof Module.register === 'function') {
      Module.register(
        new URL('./loader.mjs', pathToFileURL(__filename)).href,
        pathToFileURL(__filename).href,
      );
      esmLoaderRegistered = true;
    }
  } catch (_) {
    enqueue('runtime_capture_gap', {
      reason: 'esm_loader_registration_failed', occurrences: 1,
    }, undefined, 'incomplete');
  }
  if (typeof globalThis.fetch === 'function') {
    globalThis.fetch = wrapPromiseCall(globalThis.fetch, 'global.fetch');
  }
  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    const exports = originalLoad.apply(this, arguments);
    if (request === 'openai' || request.startsWith('openai/')) return wrapOpenAIModule(exports);
    if (request === 'undici' || request.startsWith('undici/')) return wrapUndiciModule(exports);
    return exports;
  };
  enqueue('node_runtime_ready', {
    patch_version: PATCH_VERSION,
    node_version: process.versions.node,
    queue_limit: QUEUE_LIMIT,
    is_main_thread: isMainThread,
    esm_loader_registered: esmLoaderRegistered,
  });
}
