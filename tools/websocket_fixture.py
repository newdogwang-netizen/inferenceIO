#!/usr/bin/env python3
"""Bounded loopback Responses-WebSocket fixture, not a real model provider.

The fixture emits fragmented text, duplicate final snapshots, tool calls,
usage, state references and ping/pong. It is deliberately separate from the
production proxy/normalizer, so those components see ordinary network traffic.
"""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import socket
import struct
import threading

MAX_MESSAGE = 16 << 10
MAX_CONNECTIONS = 64
ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def frame(payload: bytes, opcode=1, final=True):
    if opcode >= 8 and (len(payload) > 125 or not final):
        raise ValueError("invalid fixture control frame")
    first = (0x80 if final else 0) | opcode
    size = len(payload)
    length = bytes([size]) if size < 126 else b"\x7e"+struct.pack("!H", size) if size <= 65535 else b"\x7f"+struct.pack("!Q", size)
    return bytes([first])+length+payload


def expected_response(request):
    rid = request.get("event_id")
    metadata = request.get("metadata", {})
    index = metadata.get("fixture_index")
    if request.get("type") != "response.create" or not isinstance(rid, str) or not ID.fullmatch(rid):
        raise ValueError("invalid fixture request")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 1000:
        raise ValueError("invalid fixture index")
    padding = 32768 if index % 13 == 12 else 256
    text = f"fixture-{index}-" + "x"*padding + " 中文🙂"
    output = [{"type": "message", "id": "msg-"+rid, "role": "assistant", "content": [{"type": "output_text", "text": text}]}]
    if index % 2 == 0:
        output.append({"type": "custom_tool_call", "id": "item-"+rid, "call_id": "tool-"+rid,
                       "name": "fixture_exec", "input": f"printf turn {index}"})
    return {"id": "resp-"+rid, "status": "completed", "model": "fixture-ws-model", "output": output,
            "usage": {"input_tokens": 100+index, "output_tokens": 10+index % 7,
                      "total_tokens": 110+index+index % 7, "input_tokens_details": {"cached_tokens": 50}}}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def exact(self, n):
        value = self.rfile.read(n)
        if len(value) != n:
            raise EOFError("fixture peer closed")
        return value

    def message(self):
        chunks = bytearray()
        started = False
        while True:
            first, second = self.exact(2)
            opcode, final = first & 15, bool(first & 128)
            if first & 0x70 or not second & 0x80:
                raise ValueError("invalid client frame flags")
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", self.exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.exact(8))[0]
            if length > MAX_MESSAGE or len(chunks)+length > MAX_MESSAGE:
                raise ValueError("fixture message limit")
            if opcode >= 8 and (length > 125 or not final):
                raise ValueError("invalid client control frame")
            mask = self.exact(4)
            payload = bytes(value ^ mask[i % 4] for i, value in enumerate(self.exact(length)))
            if opcode == 8:
                self.wfile.write(frame(payload, 8))
                return None
            if opcode == 9:
                self.wfile.write(frame(payload, 10))
                continue
            if opcode == 10:
                continue
            if opcode == 1 and not started:
                started = True
            elif opcode != 0 or not started:
                raise ValueError("unsupported client data frame")
            chunks.extend(payload)
            if final:
                return json.loads(chunks.decode("utf-8"))

    def send(self, value, fragmented=False):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        if fragmented:
            split = len(raw)//2
            self.wfile.write(frame(raw[:split], 1, False)+frame(raw[split:], 0, True))
        else:
            self.wfile.write(frame(raw))

    def do_GET(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        try:
            valid_key = len(base64.b64decode(key, validate=True)) == 16
        except ValueError:
            valid_key = False
        if self.path != "/v1/responses" or self.headers.get("Upgrade", "").lower() != "websocket" or self.headers.get("Sec-WebSocket-Version") != "13" or not valid_key:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        accept = base64.b64encode(hashlib.sha1((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.connection.settimeout(1900)
        self.close_connection = True
        try:
            for _ in range(1000):
                request = self.message()
                if request is None:
                    return
                response = expected_response(request)
                rid = response["id"]
                self.send({"type": "response.created", "request_id": request["event_id"], "response": {"id": rid, "status": "in_progress"}})
                text = response["output"][0]["content"][0]["text"]
                for offset in range(0, len(text), 2048):
                    self.send({"type": "response.output_text.delta", "response_id": rid, "delta": text[offset:offset+2048]}, fragmented=True)
                for tool in response["output"][1:]:
                    self.send({"type": "response.output_item.done", "response_id": rid, "item": tool})
                self.send({"type": "response.completed", "response": response})
                self.wfile.write(frame(b"fixture-ping", 9))
        except (ValueError, UnicodeError):
            self.wfile.write(frame(struct.pack("!H", 1002), 8))
        except (OSError, EOFError):
            return


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self):
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.sockets = set()
        self.mutex = threading.Lock()
        super().__init__(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.mutex:
            self.sockets.add(request)
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.mutex:
                self.sockets.discard(request)
            self.slots.release()

    def stop(self):
        self.shutdown()
        self.thread.join(timeout=5)
        with self.mutex:
            for connection in self.sockets:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server_close()
