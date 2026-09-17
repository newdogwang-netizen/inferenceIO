"""Fail-open iorec instrumentation for the OpenAI Python SDK.

This file is embedded in the Rust binary and materialized in a private run
directory.  It intentionally uses only the Python standard library.
"""

import atexit
import builtins
import json
import os
import queue
import socket
import sys
import threading
import time
import urllib.parse
import uuid


_ENABLED = os.environ.get("IOREC_PYTHON_INJECTION") == "1"
_SOCKET = os.environ.get("IOREC_COLLECTOR_SOCKET")
_TOKEN = os.environ.get("IOREC_COLLECTOR_TOKEN")
_QUEUE_LIMIT = 256
_MAX_DEPTH = 24
_MAX_ITEMS = 10_000
_MAX_STRING_BYTES = 1 << 20
_MAX_RECORD_BYTES = 4 << 20
_MAX_STREAM_BYTES = 64 << 20
_MAX_STREAM_CHUNKS = 100_000
_SOCKET_TIMEOUT_SECONDS = 0.5
_PATCH_VERSION = 1
_SENSITIVE_KEYS = frozenset((
    "authorization",
    "api-key",
    "cookie",
    "set-cookie",
    "password",
    "proxy-authorization",
    "access-token",
    "auth-token",
    "refresh-token",
    "client-secret",
    "secret",
    "token",
    "x-api-key",
))

_events = queue.Queue(maxsize=_QUEUE_LIMIT)
_stopping = threading.Event()
_drop_lock = threading.Lock()
_drops = 0
_patch_lock = threading.RLock()
_patching = threading.local()
_original_import = builtins.__import__


def _note_drop(count=1):
    global _drops
    with _drop_lock:
        _drops += max(1, int(count))


def _take_drops():
    global _drops
    with _drop_lock:
        value = _drops
        _drops = 0
        return value


def _restore_drops(count):
    global _drops
    if count:
        with _drop_lock:
            _drops += count


def _truncate_text(value):
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= _MAX_STRING_BYTES:
        return value, False
    return encoded[:_MAX_STRING_BYTES].decode("utf-8", "ignore"), True


def _sensitive_key(value):
    lowered = value.lower().replace("_", "-")
    return lowered in _SENSITIVE_KEYS


def _sanitize(value, state=None, depth=0):
    if state is None:
        state = {"items": 0, "truncated": False, "seen": set()}
    if depth > _MAX_DEPTH or state["items"] >= _MAX_ITEMS:
        state["truncated"] = True
        return {"_iorec_omitted": "complexity_limit"}
    state["items"] += 1
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text, truncated = _truncate_text(value)
        state["truncated"] |= truncated
        return text if not truncated else {"text": text, "_iorec_truncated": True}
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) > _MAX_STRING_BYTES:
            raw = raw[:_MAX_STRING_BYTES]
            state["truncated"] = True
        return {
            "_iorec_binary_hex": raw.hex(),
            "_iorec_original_bytes": len(value),
            "_iorec_truncated": len(raw) != len(value),
        }

    identity = id(value)
    if identity in state["seen"]:
        state["truncated"] = True
        return {"_iorec_omitted": "cycle"}
    state["seen"].add(identity)
    try:
        if isinstance(value, dict):
            output = {}
            for key, item in value.items():
                if state["items"] >= _MAX_ITEMS:
                    state["truncated"] = True
                    break
                key = str(key)
                key, key_truncated = _truncate_text(key)
                state["truncated"] |= key_truncated
                output[key] = "[REDACTED]" if _sensitive_key(key) else _sanitize(
                    item, state, depth + 1
                )
            return output
        if isinstance(value, (list, tuple, set, frozenset)):
            output = []
            for item in value:
                if state["items"] >= _MAX_ITEMS:
                    state["truncated"] = True
                    break
                output.append(_sanitize(item, state, depth + 1))
            return output
        attributes = getattr(value, "__dict__", None)
        if isinstance(attributes, dict):
            return {
                "_iorec_type": type(value).__name__,
                "value": _sanitize(attributes, state, depth + 1),
            }
        return {"_iorec_type": type(value).__name__}
    except Exception:
        state["truncated"] = True
        return {"_iorec_type": type(value).__name__, "_iorec_omitted": "conversion_error"}
    finally:
        state["seen"].discard(identity)


def _submission(event, payload, inference_id=None, terminal_state=None):
    state = {"items": 0, "truncated": False, "seen": set()}
    safe = _sanitize(payload, state)
    if state["truncated"] and isinstance(safe, dict):
        safe["_iorec_capture_truncated"] = True
    if isinstance(safe, dict):
        safe["_iorec_runtime_pid"] = os.getpid()
    else:
        safe = {"value": safe, "_iorec_runtime_pid": os.getpid()}
    message = {
        "token": _TOKEN,
        "source": "python-runtime",
        "event": event,
        "payload": safe,
        "ids": {"inference_id": inference_id} if inference_id else {},
        "confidence": 1.0,
        "evidence": ["runtime_injection", "openai_python_sdk"],
    }
    if terminal_state:
        message["terminal_state"] = terminal_state
    return message, state["truncated"]


def _enqueue(event, payload, inference_id=None, terminal_state=None):
    if not (_ENABLED and _SOCKET and _TOKEN) or _stopping.is_set():
        return
    try:
        message, truncated = _submission(event, payload, inference_id, terminal_state)
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_RECORD_BYTES:
            message, _ = _submission(
                event,
                {
                    "_iorec_omitted": "record_size_limit",
                    "encoded_bytes": len(encoded),
                },
                inference_id,
                terminal_state,
            )
            encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
            truncated = True
        _events.put_nowait(encoded)
        if truncated:
            _note_drop()
    except Exception:
        _note_drop()


def _send(encoded):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(_SOCKET_TIMEOUT_SECONDS)
        client.connect(_SOCKET)
        client.sendall(encoded)
        client.shutdown(socket.SHUT_WR)
        response = client.recv(4096)
    parsed = json.loads(response.decode("utf-8"))
    return parsed.get("accepted") is True


def _send_gap(count):
    message, _ = _submission(
        "runtime_capture_gap",
        {"reason": "runtime_queue_or_submission_loss", "occurrences": count},
        terminal_state="incomplete",
    )
    return _send(json.dumps(message, separators=(",", ":")).encode("utf-8"))


def _sender():
    while not _stopping.is_set() or not _events.empty():
        try:
            encoded = _events.get(timeout=0.05)
        except queue.Empty:
            continue
        pending = _take_drops()
        try:
            if pending and not _send_gap(pending):
                _restore_drops(pending)
            if not _send(encoded):
                _note_drop()
        except Exception:
            _restore_drops(pending)
            _note_drop()
        finally:
            _events.task_done()


def _stream_next(original):
    def wrapped(self):
        inference_id = getattr(self, "_iorec_inference_id", None)
        try:
            value = original(self)
        except StopIteration:
            if inference_id and not getattr(self, "_iorec_terminal_sent", False):
                setattr(self, "_iorec_terminal_sent", True)
                _enqueue("model_stream_completed", {}, inference_id, "complete")
            raise
        except BaseException as error:
            if inference_id:
                _enqueue(
                    "model_stream_error",
                    {"error_type": type(error).__name__},
                    inference_id,
                    "error",
                )
            raise
        if inference_id:
            _enqueue("model_stream_event", {"chunk": value}, inference_id)
        return value

    wrapped._iorec_wrapped = True
    return wrapped


def _stream_anext(original):
    async def wrapped(self):
        inference_id = getattr(self, "_iorec_inference_id", None)
        try:
            value = await original(self)
        except StopAsyncIteration:
            if inference_id and not getattr(self, "_iorec_terminal_sent", False):
                setattr(self, "_iorec_terminal_sent", True)
                _enqueue("model_stream_completed", {}, inference_id, "complete")
            raise
        except BaseException as error:
            if inference_id:
                _enqueue(
                    "model_stream_error",
                    {"error_type": type(error).__name__},
                    inference_id,
                    "error",
                )
            raise
        if inference_id:
            _enqueue("model_stream_event", {"chunk": value}, inference_id)
        return value

    wrapped._iorec_wrapped = True
    return wrapped


def _is_stream(value):
    module = type(value).__module__
    name = type(value).__name__.lower()
    return module.startswith("openai") and "stream" in name


def _set_stream_context(value, inference_id):
    try:
        setattr(value, "_iorec_inference_id", inference_id)
        return True
    except Exception:
        _enqueue(
            "runtime_capture_gap",
            {"reason": "stream_object_rejected_correlation", "occurrences": 1},
            inference_id,
            "incomplete",
        )
        return False


def _safe_url(value):
    try:
        text, text_truncated = _truncate_text(str(value))
        if not isinstance(text, str):
            text = text.get("text", "")
        parsed = urllib.parse.urlsplit(text)
        host = parsed.hostname or ""
        port = parsed.port
        authority = host if port is None else "%s:%d" % (host, port)
        query_keys = []
        query_count = 0
        offset = 0
        while offset <= len(parsed.query):
            end = parsed.query.find("&", offset)
            if end < 0:
                end = len(parsed.query)
            field = parsed.query[offset:end]
            if field or offset < len(parsed.query):
                query_count += 1
                if len(query_keys) < 128:
                    key = field.split("=", 1)[0]
                    query_keys.append(urllib.parse.unquote_plus(key))
            if end == len(parsed.query):
                break
            offset = end + 1
        return {
            "scheme": parsed.scheme,
            "authority": authority,
            "path": parsed.path,
            "query_keys": query_keys,
            "query_key_count": query_count,
            "_iorec_truncated": text_truncated or query_count > len(query_keys),
        }
    except Exception:
        return {"_iorec_omitted": "url_parse_error"}


def _safe_headers(value):
    try:
        items = value.items() if hasattr(value, "items") else value
        output = {}
        count = 0
        for key, item in items:
            count += 1
            if len(output) >= 1_024:
                break
            key = str(key)
            output[key] = "[REDACTED]" if _sensitive_key(key) else str(item)
        if count > len(output):
            output["_iorec_headers_truncated"] = True
            output["_iorec_observed_header_count"] = count
        return output
    except Exception:
        return {"_iorec_omitted": "header_conversion_error"}


def _http_request(api, request):
    result = {"api": api}
    try:
        result["method"] = str(getattr(request, "method", ""))
        result["url"] = _safe_url(getattr(request, "url", ""))
        result["headers"] = _safe_headers(getattr(request, "headers", {}))
    except Exception:
        result["_iorec_capture_truncated"] = True
    return result


def _http_response(response):
    result = {}
    try:
        result["status"] = int(getattr(response, "status_code", 0))
        result["headers"] = _safe_headers(getattr(response, "headers", {}))
    except Exception:
        result["_iorec_capture_truncated"] = True
    return result


def _attach_http_stream(response, inference_id, api):
    try:
        setattr(
            response,
            "_iorec_http_capture",
            {
                "inference_id": inference_id,
                "api": api,
                "chunks": 0,
                "bytes": 0,
                "limited": False,
                "terminal": False,
            },
        )
        _enqueue("runtime_http_response_body_started", {"api": api}, inference_id)
        return True
    except Exception:
        _enqueue(
            "runtime_capture_gap",
            {"reason": "http_response_rejected_correlation", "occurrences": 1},
            inference_id,
            "incomplete",
        )
        return False


def _http_stream_chunk(response, chunk):
    context = getattr(response, "_iorec_http_capture", None)
    if not isinstance(context, dict) or context.get("terminal") or context.get("limited"):
        return
    try:
        size = len(chunk.encode("utf-8", "replace")) if isinstance(chunk, str) else len(chunk)
    except Exception:
        size = 0
    context["chunks"] += 1
    context["bytes"] += size
    if context["chunks"] > _MAX_STREAM_CHUNKS or context["bytes"] > _MAX_STREAM_BYTES:
        context["limited"] = True
        _enqueue(
            "runtime_capture_gap",
            {
                "reason": "http_response_stream_limit",
                "occurrences": 1,
                "chunks": context["chunks"],
                "bytes": context["bytes"],
            },
            context["inference_id"],
            "incomplete",
        )
        return
    _enqueue(
        "runtime_http_response_body_chunk",
        {"api": context["api"], "chunk": chunk},
        context["inference_id"],
    )


def _http_stream_terminal(response, event, terminal_state, error=None):
    context = getattr(response, "_iorec_http_capture", None)
    if not isinstance(context, dict) or context.get("terminal"):
        return
    context["terminal"] = True
    payload = {
        "api": context["api"],
        "chunks": context["chunks"],
        "bytes": context["bytes"],
        "limited": context["limited"],
    }
    if error is not None:
        payload["error_type"] = type(error).__name__
    _enqueue(event, payload, context["inference_id"], terminal_state)


def _sync_http_body_iterator(original):
    def wrapped(self, *args, **kwargs):
        try:
            iterator = original(self, *args, **kwargs)
            for chunk in iterator:
                _http_stream_chunk(self, chunk)
                yield chunk
        except GeneratorExit as error:
            _http_stream_terminal(self, "runtime_http_response_body_cancelled", "incomplete", error)
            raise
        except BaseException as error:
            _http_stream_terminal(self, "runtime_http_response_body_error", "error", error)
            raise
        else:
            context = getattr(self, "_iorec_http_capture", None)
            if isinstance(context, dict) and context.get("limited"):
                _http_stream_terminal(self, "runtime_http_response_body_incomplete", "incomplete")
            else:
                _http_stream_terminal(self, "runtime_http_response_body_completed", "complete")

    wrapped._iorec_wrapped = True
    return wrapped


def _async_http_body_iterator(original):
    async def wrapped(self, *args, **kwargs):
        try:
            iterator = original(self, *args, **kwargs)
            async for chunk in iterator:
                _http_stream_chunk(self, chunk)
                yield chunk
        except GeneratorExit as error:
            _http_stream_terminal(self, "runtime_http_response_body_cancelled", "incomplete", error)
            raise
        except BaseException as error:
            _http_stream_terminal(self, "runtime_http_response_body_error", "error", error)
            raise
        else:
            context = getattr(self, "_iorec_http_capture", None)
            if isinstance(context, dict) and context.get("limited"):
                _http_stream_terminal(self, "runtime_http_response_body_incomplete", "incomplete")
            else:
                _http_stream_terminal(self, "runtime_http_response_body_completed", "complete")

    wrapped._iorec_wrapped = True
    return wrapped


def _sync_http_send(api, original):
    def wrapped(self, request, *args, **kwargs):
        inference_id = str(uuid.uuid4())
        _enqueue("runtime_http_request_started", _http_request(api, request), inference_id)
        try:
            response = original(self, request, *args, **kwargs)
        except BaseException as error:
            _enqueue(
                "runtime_http_request_error",
                {"api": api, "error_type": type(error).__name__},
                inference_id,
                "error",
            )
            raise
        summary = _http_response(response)
        summary["api"] = api
        if bool(kwargs.get("stream", False)):
            _enqueue("runtime_http_request_completed", summary, inference_id)
            _attach_http_stream(response, inference_id, api)
        else:
            try:
                summary["body"] = response.content
                _enqueue("runtime_http_request_completed", summary, inference_id, "complete")
            except Exception:
                _enqueue("runtime_http_request_completed", summary, inference_id)
                _attach_http_stream(response, inference_id, api)
        return response

    wrapped._iorec_wrapped = True
    return wrapped


def _async_http_send(api, original):
    async def wrapped(self, request, *args, **kwargs):
        inference_id = str(uuid.uuid4())
        _enqueue("runtime_http_request_started", _http_request(api, request), inference_id)
        try:
            response = await original(self, request, *args, **kwargs)
        except BaseException as error:
            _enqueue(
                "runtime_http_request_error",
                {"api": api, "error_type": type(error).__name__},
                inference_id,
                "error",
            )
            raise
        summary = _http_response(response)
        summary["api"] = api
        if bool(kwargs.get("stream", False)):
            _enqueue("runtime_http_request_completed", summary, inference_id)
            _attach_http_stream(response, inference_id, api)
        else:
            try:
                summary["body"] = response.content
                _enqueue("runtime_http_request_completed", summary, inference_id, "complete")
            except Exception:
                _enqueue("runtime_http_request_completed", summary, inference_id)
                _attach_http_stream(response, inference_id, api)
        return response

    wrapped._iorec_wrapped = True
    return wrapped


def _sync_create(api, original):
    def wrapped(self, *args, **kwargs):
        inference_id = str(uuid.uuid4())
        _enqueue(
            "model_call_started",
            {"api": api, "args": args, "kwargs": kwargs},
            inference_id,
        )
        try:
            result = original(self, *args, **kwargs)
        except BaseException as error:
            _enqueue(
                "model_call_error",
                {"api": api, "error_type": type(error).__name__},
                inference_id,
                "error",
            )
            raise
        if _is_stream(result) and _set_stream_context(result, inference_id):
            _enqueue("model_stream_started", {"api": api}, inference_id)
        else:
            _enqueue(
                "model_call_completed",
                {"api": api, "response": result},
                inference_id,
                "complete",
            )
        return result

    wrapped._iorec_wrapped = True
    wrapped.__name__ = getattr(original, "__name__", "create")
    wrapped.__doc__ = getattr(original, "__doc__", None)
    return wrapped


def _async_create(api, original):
    async def wrapped(self, *args, **kwargs):
        inference_id = str(uuid.uuid4())
        _enqueue(
            "model_call_started",
            {"api": api, "args": args, "kwargs": kwargs},
            inference_id,
        )
        try:
            result = await original(self, *args, **kwargs)
        except BaseException as error:
            _enqueue(
                "model_call_error",
                {"api": api, "error_type": type(error).__name__},
                inference_id,
                "error",
            )
            raise
        if _is_stream(result) and _set_stream_context(result, inference_id):
            _enqueue("model_stream_started", {"api": api}, inference_id)
        else:
            _enqueue(
                "model_call_completed",
                {"api": api, "response": result},
                inference_id,
                "complete",
            )
        return result

    wrapped._iorec_wrapped = True
    wrapped.__name__ = getattr(original, "__name__", "create")
    wrapped.__doc__ = getattr(original, "__doc__", None)
    return wrapped


def _patch_class(module_name, class_name, api):
    module = sys.modules.get(module_name)
    cls = getattr(module, class_name, None) if module else None
    if not isinstance(cls, type):
        return
    original = cls.__dict__.get("create")
    if not callable(original) or getattr(original, "_iorec_wrapped", False):
        return
    if class_name.startswith("Async"):
        setattr(cls, "create", _async_create(api, original))
    else:
        setattr(cls, "create", _sync_create(api, original))


def _patch_stream_class(module_name, class_name, method_name, factory):
    module = sys.modules.get(module_name)
    cls = getattr(module, class_name, None) if module else None
    if not isinstance(cls, type):
        return
    original = cls.__dict__.get(method_name)
    if not callable(original) or getattr(original, "_iorec_wrapped", False):
        return
    setattr(cls, method_name, factory(original))


def _patch_http_method(module_name, class_name, method_name, api, factory):
    module = sys.modules.get(module_name)
    cls = getattr(module, class_name, None) if module else None
    if not isinstance(cls, type):
        return
    original = cls.__dict__.get(method_name)
    if not callable(original) or getattr(original, "_iorec_wrapped", False):
        return
    setattr(cls, method_name, factory(api, original))


def _patch_http_iterator(module_name, class_name, method_name, factory):
    module = sys.modules.get(module_name)
    cls = getattr(module, class_name, None) if module else None
    if not isinstance(cls, type):
        return
    original = cls.__dict__.get(method_name)
    if not callable(original) or getattr(original, "_iorec_wrapped", False):
        return
    setattr(cls, method_name, factory(original))


def _patch_loaded_modules():
    if getattr(_patching, "active", False):
        return
    with _patch_lock:
        _patching.active = True
        try:
            for module_name, class_name, api in (
                ("openai.resources.chat.completions.completions", "Completions", "chat.completions"),
                ("openai.resources.chat.completions.completions", "AsyncCompletions", "chat.completions"),
                ("openai.resources.responses.responses", "Responses", "responses"),
                ("openai.resources.responses.responses", "AsyncResponses", "responses"),
            ):
                _patch_class(module_name, class_name, api)
            for module_name, class_name, method_name, factory in (
                ("openai._streaming", "Stream", "__next__", _stream_next),
                ("openai._streaming", "AsyncStream", "__anext__", _stream_anext),
            ):
                _patch_stream_class(module_name, class_name, method_name, factory)
            for module_name, class_name, method_name, api, factory in (
                ("httpx", "Client", "send", "httpx.Client.send", _sync_http_send),
                ("httpx", "AsyncClient", "send", "httpx.AsyncClient.send", _async_http_send),
                ("requests", "Session", "send", "requests.Session.send", _sync_http_send),
            ):
                _patch_http_method(module_name, class_name, method_name, api, factory)
            for module_name, class_name, method_name, factory in (
                ("httpx", "Response", "iter_raw", _sync_http_body_iterator),
                ("httpx", "Response", "aiter_raw", _async_http_body_iterator),
                ("requests", "Response", "iter_content", _sync_http_body_iterator),
            ):
                _patch_http_iterator(module_name, class_name, method_name, factory)
        except Exception:
            _note_drop()
        finally:
            _patching.active = False


def _instrumented_import(name, globals=None, locals=None, fromlist=(), level=0):
    module = _original_import(name, globals, locals, fromlist, level)
    if name in ("openai", "httpx", "requests") or name.startswith(
        ("openai.", "httpx.", "requests.")
    ):
        _patch_loaded_modules()
    return module


def _after_fork_child():
    global _events, _stopping, _drop_lock, _patch_lock, _patching, _drops, _sender_thread
    _events = queue.Queue(maxsize=_QUEUE_LIMIT)
    _stopping = threading.Event()
    _drop_lock = threading.Lock()
    _patch_lock = threading.RLock()
    _patching = threading.local()
    _drops = 0
    _sender_thread = threading.Thread(target=_sender, name="iorec-python-sender", daemon=True)
    _sender_thread.start()
    _enqueue(
        "python_runtime_ready",
        {
            "patch_version": _PATCH_VERSION,
            "python_version": "%d.%d.%d" % sys.version_info[:3],
            "queue_limit": _QUEUE_LIMIT,
            "fork_child": True,
        },
    )


def _shutdown():
    if not _ENABLED:
        return
    builtins.__import__ = _original_import
    deadline = time.monotonic() + 1.0
    while not _events.empty() and time.monotonic() < deadline:
        time.sleep(0.01)
    pending = _take_drops()
    if pending:
        try:
            _send_gap(pending)
        except Exception:
            pass
    _stopping.set()
    if "_sender_thread" in globals():
        _sender_thread.join(timeout=0.2)


if _ENABLED and _SOCKET and _TOKEN:
    _sender_thread = threading.Thread(target=_sender, name="iorec-python-sender", daemon=True)
    _sender_thread.start()
    builtins.__import__ = _instrumented_import
    if hasattr(os, "register_at_fork"):
        os.register_at_fork(after_in_child=_after_fork_child)
    atexit.register(_shutdown)
    _patch_loaded_modules()
    _enqueue(
        "python_runtime_ready",
        {
            "patch_version": _PATCH_VERSION,
            "python_version": "%d.%d.%d" % sys.version_info[:3],
            "queue_limit": _QUEUE_LIMIT,
        },
    )
