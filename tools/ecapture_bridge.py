#!/usr/bin/python3
"""Strict eCapture-to-iorec probe protocol bridge.

The bridge intentionally consumes eCapture's synchronous ``--debug --hex``
stdout instead of the eCaptureQ WebSocket hub.  The upstream v2.6.0 hub has
unacknowledged, uncounted non-blocking drop paths; using it would make a zero
drop claim unverifiable.  Debug text mode exposes perf loss and decode/dispatch
failures while hex mode preserves the raw TLS bytes.

Install this file beside a private ``ecapture-bridge.json`` (or invoke it from
a trusted wrapper with ``--config``).  The config pins the upstream executable
by SHA-256.  The upstream executable itself must carry the narrowly required
file capabilities or otherwise be launched by a separately controlled
privilege boundary; the recorder and target stay unprivileged.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from queue import Empty, Queue
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


PROTOCOL_VERSION = 2
HELPER_VERSION = "1.1.0"
MAX_CONFIG_BYTES = 64 * 1024
MAX_TARGET_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_LABEL_BYTES = 256
MAX_OCCURRENCES = (1 << 63) - 1
MAX_TRACKED_PIDS = 1_000_000
MAX_CONNECTIONS = 1_000_000
MAX_UPSTREAM_LINE_BYTES = MAX_PAYLOAD_BYTES * 8 + 64 * 1024
MAX_HEX_TEXT_BYTES = MAX_PAYLOAD_BYTES * 6 + 4096
UPSTREAM_QUEUE_RECORDS = 1024
CGROUP_SAMPLE_SECONDS = 0.01
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,255}$")
RUN_ID_RE = re.compile(r"^run-[A-Za-z0-9-]{1,240}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
EVENT_HEADER_RE = re.compile(
    r"^\S+ INF (?:\[[^\]\r\n]{1,64}\] )?"
    r"PID:(?P<pid>[0-9]+) TID:(?P<tid>[0-9]+) Comm:(?P<comm>.*?) "
    r"FD:(?P<fd>[0-9]+) (?P<direction>WRITE|READ) "
    r"\((?P<length>[0-9]+) bytes, hex\):"
)
GOTLS_EVENT_HEADER_RE = re.compile(
    r"^\S+ INF PID:(?P<pid>[0-9]+), TID:(?P<tid>[0-9]+), "
    r"Comm:(?P<comm>[^,\r\n]{0,255}), FD:(?P<fd>[0-9]+), "
    r"Tuple:(?P<tuple>\S{1,512}), Type:(?P<direction>WRITE|READ), "
    r"Len:(?P<length>[0-9]+)$"
)
GOTLS_DATA_MARKER = "Data(hex):"
GOTLS_HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")
CONNECTION_RE = re.compile(
    r"^\S+ INF PID:(?P<pid>[0-9]+), Comm:.*?, TID:(?P<tid>[0-9]+), "
    r"FD:(?P<fd>[0-9]+), Tuple: (?P<tuple>\S+)"
)
LOST_RE = re.compile(r"lost_samples[=:\s]+(?P<count>[0-9]+)", re.IGNORECASE)
HEX_LINE_RE = re.compile(r"^[0-9A-Fa-f]{4,8}\s{2}")
READY_RE = re.compile(r"^\S+ INF probe started successfully\.")


class BridgeError(RuntimeError):
    """A bounded, credential-free bridge failure."""


@dataclass(frozen=True)
class BridgeConfig:
    upstream_path: Path
    upstream_sha256: str
    upstream_release: str
    module: str
    libssl: Path | None
    mapsize_kib: int
    perf_reorder_lag_ms: int
    readiness_timeout_seconds: int
    shutdown_drain_seconds: int
    max_payload_bytes: int


@dataclass
class PendingEvent:
    pid: int
    tid: int
    fd: int
    direction: str
    declared_length: int
    encoding: str = "offset-hex"
    connection_tuple: str | None = None
    data_marker_seen: bool = False
    hex_lines: list[str] = field(default_factory=list)
    hex_text_bytes: int = 0


def _bounded_label(value: object, name: str) -> str:
    if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
        raise BridgeError(f"invalid {name}")
    if len(value.encode("utf-8")) > MAX_LABEL_BYTES:
        raise BridgeError(f"invalid {name}")
    return value


def _validate_trusted_file(path: Path, *, executable: bool) -> Path:
    if not path.is_absolute():
        raise BridgeError("trusted file path must be absolute")
    try:
        before = path.lstat()
    except OSError as exc:
        raise BridgeError("trusted file is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BridgeError("trusted file must be a non-symlink regular file")
    if before.st_uid not in (0, os.geteuid()):
        raise BridgeError("trusted file owner is not accepted")
    if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BridgeError("trusted file is group/other writable")
    if executable and not before.st_mode & stat.S_IXUSR:
        raise BridgeError("trusted executable is not owner-executable")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BridgeError("trusted file cannot be resolved") from exc
    if resolved != path:
        raise BridgeError("trusted file path must already be canonical")

    current = resolved.parent
    while True:
        meta = current.stat()
        if not stat.S_ISDIR(meta.st_mode):
            raise BridgeError("trusted path ancestor is not a directory")
        if meta.st_uid not in (0, os.geteuid()):
            raise BridgeError("trusted path ancestor owner is not accepted")
        writable = meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        if writable and not meta.st_mode & stat.S_ISVTX:
            raise BridgeError("trusted path ancestor is group/other writable")
        if current == current.parent:
            break
        current = current.parent
    return resolved


def _hash_file(path: Path, max_bytes: int | None = None) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BridgeError("file cannot be opened safely") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise BridgeError("file changed identity")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise BridgeError("file exceeds bridge hashing limit")
                digest.update(chunk)
        after = path.stat()
        identity_before = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise BridgeError("file changed while being hashed")
    finally:
        os.close(fd)
    return "sha256:" + digest.hexdigest()


def load_config(path: Path) -> BridgeConfig:
    trusted = _validate_trusted_file(path, executable=False)
    if trusted.stat().st_size > MAX_CONFIG_BYTES:
        raise BridgeError("bridge config exceeds size limit")
    try:
        raw = json.loads(trusted.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BridgeError("bridge config is not valid JSON") from exc
    allowed = {
        "schema_version",
        "upstream_path",
        "upstream_sha256",
        "upstream_release",
        "module",
        "libssl",
        "mapsize_kib",
        "perf_reorder_lag_ms",
        "readiness_timeout_seconds",
        "shutdown_drain_seconds",
        "max_payload_bytes",
    }
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise BridgeError("bridge config has unknown fields")
    if raw.get("schema_version") != 1:
        raise BridgeError("bridge config schema version is unsupported")
    upstream = _validate_trusted_file(Path(raw.get("upstream_path", "")), executable=True)
    expected = raw.get("upstream_sha256")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise BridgeError("bridge config upstream digest is invalid")
    if _hash_file(upstream) != expected:
        raise BridgeError("configured eCapture digest does not match")
    release = _bounded_label(raw.get("upstream_release"), "upstream release")
    module = raw.get("module", "tls")
    if module not in ("tls", "gotls"):
        raise BridgeError("eCapture module must be tls or gotls")
    libssl_raw = raw.get("libssl")
    libssl = None
    if libssl_raw is not None:
        libssl = _validate_trusted_file(Path(libssl_raw), executable=False)
    if module == "gotls" and libssl is not None:
        raise BridgeError("libssl is valid only for the eCapture tls module")
    mapsize = raw.get("mapsize_kib", 4096)
    lag = raw.get("perf_reorder_lag_ms", 10)
    ready = raw.get("readiness_timeout_seconds", 20)
    shutdown_drain = raw.get("shutdown_drain_seconds", 2)
    max_payload = raw.get("max_payload_bytes", MAX_PAYLOAD_BYTES)
    if not isinstance(mapsize, int) or not 1024 <= mapsize <= 65536:
        raise BridgeError("mapsize_kib is outside 1024..65536")
    if not isinstance(lag, int) or not 1 <= lag <= 1000:
        raise BridgeError("perf_reorder_lag_ms is outside 1..1000")
    if not isinstance(ready, int) or not 1 <= ready <= 60:
        raise BridgeError("readiness_timeout_seconds is outside 1..60")
    if not isinstance(shutdown_drain, int) or not 0 <= shutdown_drain <= 5:
        raise BridgeError("shutdown_drain_seconds is outside 0..5")
    if not isinstance(max_payload, int) or not 1 <= max_payload <= MAX_PAYLOAD_BYTES:
        raise BridgeError("max_payload_bytes is outside the protocol limit")
    return BridgeConfig(
        upstream,
        expected,
        release,
        module,
        libssl,
        mapsize,
        lag,
        ready,
        shutdown_drain,
        max_payload,
    )


def _cgroup_relative(path: Path) -> str:
    root = Path("/sys/fs/cgroup")
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise BridgeError("target cgroup is outside the unified hierarchy") from exc
    if not (resolved / "cgroup.procs").is_file():
        raise BridgeError("target cgroup has no cgroup.procs")
    return "/" + relative.as_posix().strip("/")


def _pid_in_cgroup(pid: int, relative: str) -> bool:
    try:
        entries = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return False
    return any(line == f"0::{relative}" for line in entries)


def _parse_decimal(value: str, maximum: int) -> int:
    normalized = value.lstrip("0") or "0"
    limit = str(maximum)
    if len(normalized) > len(limit) or (len(normalized) == len(limit) and normalized > limit):
        raise BridgeError("eCapture numeric field exceeds its limit")
    return int(normalized)


def _loss_occurrences(value: str) -> int:
    try:
        return max(1, _parse_decimal(value, MAX_OCCURRENCES))
    except BridgeError:
        return MAX_OCCURRENCES


def _decode_hex(lines: list[str], expected: int) -> bytes:
    encoded = []
    next_offset = 0
    for line in lines:
        if not HEX_LINE_RE.match(line):
            continue
        offset_text = line.split(None, 1)[0]
        offset = int(offset_text, 16)
        if offset != next_offset:
            raise BridgeError("eCapture hex offsets are discontinuous")
        body = line[len(offset_text) :].lstrip()
        data_region = re.split(r"\s{4,}", body, maxsplit=1)[0]
        digits = re.sub(r"\s+", "", data_region)
        if not digits or len(digits) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
            raise BridgeError("eCapture hex payload is malformed")
        encoded.append(digits)
        next_offset += len(digits) // 2
    payload = bytes.fromhex("".join(encoded)) if encoded else b""
    if len(payload) != expected:
        raise BridgeError("eCapture payload length disagrees with its header")
    return payload


def _decode_contiguous_hex(lines: list[str], expected: int) -> bytes:
    if len(lines) != 1:
        raise BridgeError("eCapture GoTLS event must contain one bounded hex line")
    encoded = lines[0]
    if not GOTLS_HEX_RE.fullmatch(encoded) or len(encoded) % 2:
        raise BridgeError("eCapture GoTLS hex payload is malformed")
    if len(encoded) // 2 != expected:
        raise BridgeError("eCapture GoTLS payload length disagrees with its header")
    return bytes.fromhex(encoded)


def _canonical_gotls_tuple(value: str) -> str:
    endpoints = value.split("->")
    if len(endpoints) != 2 or any(not endpoint or len(endpoint) > 256 for endpoint in endpoints):
        raise BridgeError("eCapture GoTLS connection tuple is malformed")
    return "<->".join(sorted(endpoints))


def _emit(record: dict[str, object], output: BinaryIO = sys.stdout.buffer) -> None:
    encoded = json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    output.write(encoded + b"\n")
    output.flush()


class Bridge:
    def __init__(
        self,
        args: argparse.Namespace,
        config: BridgeConfig,
        output: BinaryIO = sys.stdout.buffer,
    ) -> None:
        self.args = args
        self.config = config
        self.output = output
        self.pending: PendingEvent | None = None
        self.connections: dict[tuple[int, int, int], str] = {}
        self.latest_connection: dict[tuple[int, int], str] = {}
        self.allowed_pids: set[int] = {args.target_pid}
        self.allowed_pids_lock = threading.Lock()
        self.cgroup_tracker_stop = threading.Event()
        self.cgroup_tracking_failed = False
        self.connection_tracking_failed = False
        self.upstream_line_overflow = False
        self.events = 0
        self.drops = 0
        self.probe_hits = 0
        self.ready = False
        self.stop_requested = False
        self.child: subprocess.Popen[bytes] | None = None
        self.diagnostic_bytes = 0
        self.shutdown_timer: threading.Timer | None = None

    def gap(self, reason: str, occurrences: int = 1) -> None:
        occurrences = max(1, min(occurrences, MAX_OCCURRENCES))
        self.drops = min(self.drops + occurrences, MAX_OCCURRENCES)
        _emit(
            {"type": "gap", "schema_version": PROTOCOL_VERSION, "reason": reason, "occurrences": occurrences},
            self.output,
        )

    def _connection_id(self, event: PendingEvent) -> str:
        value = event.connection_tuple
        if value is None:
            value = self.connections.get((event.pid, event.tid, event.fd))
        if value is None:
            value = self.latest_connection.get((event.pid, event.tid))
        seed = value or f"pid={event.pid};tid={event.tid};fd={event.fd}"
        return "ecapture-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

    def finish_event(self) -> None:
        event = self.pending
        self.pending = None
        if event is None:
            return
        try:
            if event.declared_length > self.config.max_payload_bytes:
                raise BridgeError("eCapture payload exceeds configured limit")
            if event.encoding == "contiguous-hex":
                if not event.data_marker_seen:
                    raise BridgeError("eCapture GoTLS data marker is absent")
                payload = _decode_contiguous_hex(event.hex_lines, event.declared_length)
            else:
                payload = _decode_hex(event.hex_lines, event.declared_length)
            with self.allowed_pids_lock:
                previously_observed = event.pid in self.allowed_pids
            if not previously_observed:
                if not _pid_in_cgroup(event.pid, self.args.cgroup_relative):
                    raise BridgeError("eCapture emitted an event outside the target cgroup")
                with self.allowed_pids_lock:
                    if len(self.allowed_pids) >= MAX_TRACKED_PIDS:
                        raise BridgeError("target cgroup PID history exceeds its limit")
                    self.allowed_pids.add(event.pid)
            self.probe_hits += 1
            if not payload:
                return
            digest = hashlib.sha256(payload).hexdigest()
            _emit(
                {
                    "type": "evidence",
                    "schema_version": PROTOCOL_VERSION,
                    "event": "tls_plaintext",
                    "pid": event.pid,
                    "tid": event.tid,
                    "connection_id": self._connection_id(event),
                    "direction": event.direction.lower(),
                    "protocol": "tls",
                    "media_type": "application/octet-stream",
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "payload_sha256": "sha256:" + digest,
                    "confidence": 1.0,
                },
                self.output,
            )
            self.events += 1
        except BridgeError:
            self.gap("upstream_event_parse_or_binding_failed")

    def process_line(self, raw: bytes) -> None:
        line = ANSI_RE.sub("", raw.decode("utf-8", errors="replace")).rstrip("\r\n")
        header = EVENT_HEADER_RE.search(line)
        if header:
            self.finish_event()
            try:
                declared_length = _parse_decimal(
                    header.group("length"), self.config.max_payload_bytes
                )
                pid = _parse_decimal(header.group("pid"), (1 << 31) - 1)
                tid = _parse_decimal(header.group("tid"), (1 << 31) - 1)
                fd = _parse_decimal(header.group("fd"), (1 << 31) - 1)
            except BridgeError:
                self.gap("upstream_event_parse_or_binding_failed")
                return
            self.pending = PendingEvent(
                pid=pid,
                tid=tid,
                fd=fd,
                direction=header.group("direction"),
                declared_length=declared_length,
            )
            return
        gotls_header = GOTLS_EVENT_HEADER_RE.fullmatch(line)
        if gotls_header:
            self.finish_event()
            try:
                declared_length = _parse_decimal(
                    gotls_header.group("length"), self.config.max_payload_bytes
                )
                pid = _parse_decimal(gotls_header.group("pid"), (1 << 31) - 1)
                tid = _parse_decimal(gotls_header.group("tid"), (1 << 31) - 1)
                fd = _parse_decimal(gotls_header.group("fd"), (1 << 31) - 1)
            except BridgeError:
                self.gap("upstream_event_parse_or_binding_failed")
                return
            try:
                connection_tuple = _canonical_gotls_tuple(gotls_header.group("tuple"))
            except BridgeError:
                self.gap("upstream_event_parse_or_binding_failed")
                return
            self.pending = PendingEvent(
                pid=pid,
                tid=tid,
                fd=fd,
                direction=gotls_header.group("direction"),
                declared_length=declared_length,
                encoding="contiguous-hex",
                connection_tuple=connection_tuple,
            )
            return
        if (
            self.pending is not None
            and self.pending.encoding == "contiguous-hex"
            and line == GOTLS_DATA_MARKER
        ):
            if self.pending.data_marker_seen:
                self.finish_event()
                self.gap("upstream_event_parse_or_binding_failed")
                return
            self.pending.data_marker_seen = True
            return
        if (
            self.pending is not None
            and self.pending.encoding == "contiguous-hex"
            and self.pending.data_marker_seen
        ):
            if len(line.encode("ascii", errors="ignore")) != len(line):
                self.finish_event()
                self.gap("upstream_event_parse_or_binding_failed")
                return
            self.pending.hex_text_bytes += len(line)
            if self.pending.hex_text_bytes > MAX_HEX_TEXT_BYTES:
                self.pending = None
                self.gap("upstream_event_parse_or_binding_failed")
                return
            self.pending.hex_lines.append(line)
            self.finish_event()
            return
        if self.pending is not None and HEX_LINE_RE.match(line):
            self.pending.hex_text_bytes += len(line.encode("utf-8"))
            if self.pending.hex_text_bytes > MAX_HEX_TEXT_BYTES:
                self.pending = None
                self.gap("upstream_event_parse_or_binding_failed")
                return
            self.pending.hex_lines.append(line)
            return
        if self.pending is not None and line.startswith("20"):
            self.finish_event()

        connection = CONNECTION_RE.search(line)
        if connection:
            try:
                key = (
                    _parse_decimal(connection.group("pid"), (1 << 31) - 1),
                    _parse_decimal(connection.group("tid"), (1 << 31) - 1),
                    _parse_decimal(connection.group("fd"), (1 << 31) - 1),
                )
            except BridgeError:
                self.gap("upstream_event_parse_or_binding_failed")
                key = (0, 0, 0)
        else:
            key = (0, 0, 0)
        if connection and key[0] > 0:
            if key not in self.connections and len(self.connections) >= MAX_CONNECTIONS:
                if not self.connection_tracking_failed:
                    self.connection_tracking_failed = True
                    self.gap("connection_identity_limit_exceeded")
            else:
                self.connections[key] = connection.group("tuple")
                self.latest_connection[(key[0], key[1])] = connection.group("tuple")

        if "Perf buffer full, samples lost" in line:
            match = LOST_RE.search(line)
            self.gap(
                "ring_buffer_samples_lost",
                _loss_occurrences(match.group("count")) if match else 1,
            )
        elif "Event not ready, skipping" in line:
            self.gap("upstream_event_not_ready")
        elif "Failed to decode event" in line:
            self.gap("upstream_event_decode_failed")
        elif "Failed to dispatch event" in line or "Handler failed to process event" in line:
            self.gap("upstream_event_dispatch_failed")

        if not self.ready and READY_RE.search(line):
            self.ready = True
            upstream_version = f"{self.config.upstream_release}+{self.config.upstream_sha256[7:19]}"
            capabilities = ["tls_plaintext", "cgroup_filter", "drop_reporting", "payload_bytes"]
            if self.config.module == "gotls":
                capabilities.append("go_tls_plaintext")
            _emit(
                {
                    "type": "ready",
                    "schema_version": PROTOCOL_VERSION,
                    "helper": "ecapture-bridge",
                    "helper_version": HELPER_VERSION,
                    "upstream_name": "ecapture",
                    "upstream_version": upstream_version,
                    "capabilities": capabilities,
                    "target_pid": self.args.target_pid,
                    "target_executable_sha256": self.args.target_executable_sha256,
                    "target_cgroup": str(self.args.target_cgroup),
                    "filter_scope": "cgroup",
                },
                self.output,
            )

    def request_stop(self, _signum: int, _frame: object) -> None:
        if self.stop_requested:
            self._signal_child_stop()
            return
        self.stop_requested = True
        self.shutdown_timer = threading.Timer(
            self.config.shutdown_drain_seconds,
            self._signal_child_stop,
        )
        self.shutdown_timer.daemon = True
        self.shutdown_timer.start()

    def _signal_child_stop(self) -> None:
        if self.child is not None and self.child.poll() is None:
            try:
                self.child.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass

    def _drain_stderr(self, stream: BinaryIO) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            self.diagnostic_bytes += len(chunk)

    def _track_cgroup_members(self) -> None:
        path = self.args.target_cgroup / "cgroup.procs"
        while not self.cgroup_tracker_stop.is_set():
            try:
                values = path.read_text(encoding="ascii").splitlines()
                pids = {int(value) for value in values if value.isascii() and value.isdecimal()}
                if any(pid <= 0 or pid > (1 << 31) - 1 for pid in pids):
                    raise ValueError("invalid PID in target cgroup")
                with self.allowed_pids_lock:
                    new_pids = pids.difference(self.allowed_pids)
                    if len(self.allowed_pids) + len(new_pids) > MAX_TRACKED_PIDS:
                        raise ValueError("target cgroup PID history exceeds its limit")
                    self.allowed_pids.update(new_pids)
            except (OSError, UnicodeError, ValueError):
                self.cgroup_tracking_failed = True
                return
            self.cgroup_tracker_stop.wait(CGROUP_SAMPLE_SECONDS)

    def _read_stdout(self, stream: BinaryIO, output: Queue[bytes | None]) -> None:
        try:
            while True:
                line = stream.readline(MAX_UPSTREAM_LINE_BYTES + 2)
                if not line:
                    break
                if len(line) > MAX_UPSTREAM_LINE_BYTES or not line.endswith(b"\n"):
                    self.upstream_line_overflow = True
                    while line and not line.endswith(b"\n"):
                        line = stream.readline(MAX_UPSTREAM_LINE_BYTES + 2)
                    continue
                output.put(line)
        finally:
            output.put(None)

    def run(self) -> int:
        command = [
            str(self.config.upstream_path),
            self.config.module,
            "-m",
            "text",
            "--debug",
            "--hex",
            "--perf-reorder",
            f"--perf-reorder-lag-ms={self.config.perf_reorder_lag_ms}",
            f"--mapsize={self.config.mapsize_kib}",
            f"--cgroup_path={self.args.target_cgroup}",
        ]
        if self.config.libssl is not None:
            command.append(f"--libssl={self.config.libssl}")
        if self.config.module == "gotls":
            command.append(f"--elfpath={self.args.target_executable}")
        try:
            self.child = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C"},
                close_fds=True,
            )
        except OSError as exc:
            raise BridgeError("eCapture could not be started") from exc
        assert self.child.stdout is not None and self.child.stderr is not None
        if self.stop_requested:
            self._signal_child_stop()
        stderr_thread = threading.Thread(target=self._drain_stderr, args=(self.child.stderr,), daemon=True)
        stdout_lines: Queue[bytes | None] = Queue(maxsize=UPSTREAM_QUEUE_RECORDS)
        stdout_thread = threading.Thread(
            target=self._read_stdout,
            args=(self.child.stdout, stdout_lines),
            daemon=True,
        )
        cgroup_thread = threading.Thread(target=self._track_cgroup_members, daemon=True)
        stderr_thread.start()
        stdout_thread.start()
        cgroup_thread.start()

        deadline = time.monotonic() + self.config.readiness_timeout_seconds
        try:
            while True:
                wait_seconds = 0.2
                if not self.ready:
                    wait_seconds = max(0.0, min(wait_seconds, deadline - time.monotonic()))
                try:
                    raw = stdout_lines.get(timeout=wait_seconds)
                except Empty:
                    raw = b""
                if raw is None:
                    break
                if raw:
                    self.process_line(raw)
                if not self.ready and time.monotonic() >= deadline:
                    self._signal_child_stop()
                    raise BridgeError("eCapture readiness deadline expired")
                if not raw and self.child.poll() is not None and not stdout_thread.is_alive():
                    break
            self.finish_event()
            code = self.child.wait()
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            self.cgroup_tracker_stop.set()
            cgroup_thread.join(timeout=2)
            if not self.ready:
                raise BridgeError("eCapture exited before probe readiness")
            if self.cgroup_tracking_failed or cgroup_thread.is_alive():
                self.gap("cgroup_membership_tracking_failed")
            if self.diagnostic_bytes > MAX_DIAGNOSTIC_BYTES:
                self.gap("upstream_stderr_limit_exceeded")
            if self.upstream_line_overflow:
                self.gap("upstream_line_limit_exceeded")
            if self.probe_hits == 0:
                self.gap("no_probe_hits")
            if code != 0:
                self.gap("upstream_nonzero_exit")
            complete = self.stop_requested and code == 0 and self.drops == 0
            _emit(
                {
                    "type": "final",
                    "schema_version": PROTOCOL_VERSION,
                    "captured_events": self.events,
                    "dropped_events": self.drops,
                    "probe_hits": self.probe_hits,
                    "complete": complete,
                },
                self.output,
            )
            return 0 if complete else 1
        finally:
            if self.shutdown_timer is not None:
                self.shutdown_timer.cancel()
            self.cgroup_tracker_stop.set()
            if self.child.poll() is None:
                self._signal_child_stop()
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            cgroup_thread.join(timeout=2)
            self.child.stdout.close()
            self.child.stderr.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--iorec-probe-protocol", type=int, required=True)
    parser.add_argument("--target-pid", type=int, required=True)
    parser.add_argument("--target-executable", type=Path, required=True)
    parser.add_argument("--target-executable-sha256", required=True)
    parser.add_argument("--filter-scope", choices=("pid_tree", "cgroup"), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--target-cgroup", type=Path)
    args = parser.parse_args(argv)
    if args.iorec_probe_protocol != PROTOCOL_VERSION:
        raise BridgeError("iorec probe protocol version is unsupported")
    if not 1 <= args.target_pid <= (1 << 31) - 1:
        raise BridgeError("target PID is invalid")
    if not SHA256_RE.fullmatch(args.target_executable_sha256):
        raise BridgeError("target executable digest is invalid")
    if not RUN_ID_RE.fullmatch(args.run_id):
        raise BridgeError("run ID is invalid")
    if args.filter_scope != "cgroup" or args.target_cgroup is None:
        raise BridgeError("eCapture bridge requires iorec cgroup filtering")
    executable = _validate_trusted_file(args.target_executable, executable=True)
    if _hash_file(executable, MAX_TARGET_BYTES) != args.target_executable_sha256:
        raise BridgeError("target executable digest does not match")
    args.target_executable = executable
    args.target_cgroup = args.target_cgroup.resolve(strict=True)
    args.cgroup_relative = _cgroup_relative(args.target_cgroup)
    if not _pid_in_cgroup(args.target_pid, args.cgroup_relative):
        raise BridgeError("target PID is not in the declared cgroup")
    return args


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = parse_args(argv)
        config_path = args.config
        if config_path is None:
            config_path = Path(sys.argv[0]).resolve().with_name("ecapture-bridge.json")
        config = load_config(config_path.resolve(strict=True))
        bridge = Bridge(args, config)
        signal.signal(signal.SIGTERM, bridge.request_stop)
        signal.signal(signal.SIGINT, bridge.request_stop)
        return bridge.run()
    except (BridgeError, OSError) as exc:
        # Diagnostics deliberately expose only the bounded error class/message;
        # never forward upstream output because it may contain credentials.
        print(f"ecapture bridge: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
