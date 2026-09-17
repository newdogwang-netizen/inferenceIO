#!/usr/bin/python3
"""Strict AgentSight process-event bridge for iorec probe protocol v2.

The bridge runs a digest-pinned AgentSight ``debug process`` command with a
kernel cgroup-v2 filter and converts its process, file, network, coordination,
and memory events into encrypted iorec probe evidence.  AgentSight v1.0.25
does not count BPF ring-buffer reservation failures, so this bridge always
reports that limitation as a gap instead of claiming complete coverage.
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
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import BinaryIO


PROTOCOL_VERSION = 2
HELPER_VERSION = "1.0.0"
MAX_CONFIG_BYTES = 64 * 1024
MAX_TARGET_BYTES = 512 * 1024 * 1024
MAX_UPSTREAM_BYTES = 512 * 1024 * 1024
MAX_EVENT_BYTES = 512 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_LABEL_BYTES = 256
MAX_TRACKED_PIDS = 1_000_000
MAX_EVENTS = 10_000_000
MAX_OCCURRENCES = (1 << 63) - 1
UPSTREAM_QUEUE_RECORDS = 1024
CGROUP_SAMPLE_SECONDS = 0.01
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,255}$")
RUN_ID_RE = re.compile(r"^run-[A-Za-z0-9-]{1,240}$")
KNOWN_BANNER_LINES = {
    "Raw Process Events",
    "Starting process event stream with raw JSON output (press Ctrl+C to stop):",
    "Received shutdown signal, shutting down...",
    "[HTTPFilter Global Metrics] No metrics available",
    "[SSLFilter Global Metrics] No metrics available",
    "✓ Shutdown requested. Stopping monitoring.",
}
FILE_SUMMARY_TYPES = {
    "FILE_DELETE",
    "FILE_RENAME",
    "DIR_CREATE",
    "FILE_TRUNCATE",
    "CHDIR",
    "WRITE",
}
NETWORK_SUMMARY_TYPES = {"NET_BIND", "NET_LISTEN", "NET_CONNECT"}
PROCESS_SUMMARY_TYPES = {"PGRP_CHANGE", "SESSION_CREATE", "SIGNAL_SEND", "PROC_FORK"}
MEMORY_SUMMARY_TYPES = {"MMAP_SHARED", "COW_FAULT"}


class BridgeError(RuntimeError):
    """A bounded, credential-free bridge failure."""


@dataclass(frozen=True)
class BridgeConfig:
    upstream_path: Path
    upstream_sha256: str
    upstream_release: str
    privilege_mode: str
    sudo_path: Path | None
    readiness_timeout_seconds: int
    shutdown_drain_seconds: int
    max_event_bytes: int


def _bounded_label(value: object, name: str) -> str:
    if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
        raise BridgeError(f"invalid {name}")
    if len(value.encode("utf-8")) > MAX_LABEL_BYTES:
        raise BridgeError(f"invalid {name}")
    return value


def _validate_trusted_file(
    path: Path,
    *,
    executable: bool,
    require_root_chain: bool = False,
) -> Path:
    if not path.is_absolute():
        raise BridgeError("trusted file path must be absolute")
    try:
        before = path.lstat()
    except OSError as exc:
        raise BridgeError("trusted file is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BridgeError("trusted file must be a non-symlink regular file")
    accepted_owners = (0,) if require_root_chain else (0, os.geteuid())
    if before.st_uid not in accepted_owners:
        raise BridgeError("trusted file owner is not accepted")
    if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BridgeError("trusted file is group/other writable")
    if executable and not before.st_mode & stat.S_IXUSR:
        raise BridgeError("trusted executable is not owner-executable")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise BridgeError("trusted file path must already be canonical")
    after = resolved.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise BridgeError("trusted file changed during validation")
    parent = resolved.parent
    while True:
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise BridgeError("trusted file ancestor is not a directory")
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if metadata.st_uid not in accepted_owners:
            raise BridgeError("trusted file ancestor owner is not accepted")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not sticky_root:
            raise BridgeError("trusted file ancestor is group/other writable")
        if require_root_chain and sticky_root:
            raise BridgeError("privileged executable cannot be reached through a writable ancestor")
        if parent == Path("/"):
            break
        parent = parent.parent
    return resolved


def _hash_file(path: Path, limit: int) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BridgeError("trusted file metadata is unavailable") from exc
    if size > limit:
        raise BridgeError("trusted file exceeds its byte limit")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise BridgeError("trusted file exceeds its byte limit")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _read_config(path: Path) -> dict[str, object]:
    trusted = _validate_trusted_file(path, executable=False)
    if trusted.stat().st_size > MAX_CONFIG_BYTES:
        raise BridgeError("bridge configuration exceeds its byte limit")
    try:
        value = json.loads(trusted.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError, RecursionError, OSError) as exc:
        raise BridgeError("bridge configuration is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BridgeError("bridge configuration must be a JSON object")
    return value


def load_config(path: Path) -> BridgeConfig:
    raw = _read_config(path)
    allowed = {
        "schema_version",
        "upstream_path",
        "upstream_sha256",
        "upstream_release",
        "privilege_mode",
        "sudo_path",
        "readiness_timeout_seconds",
        "shutdown_drain_seconds",
        "max_event_bytes",
    }
    if set(raw) != allowed:
        raise BridgeError("bridge configuration fields do not match schema v1")
    if raw.get("schema_version") != 1:
        raise BridgeError("bridge configuration schema is unsupported")
    privilege_mode = raw.get("privilege_mode")
    if privilege_mode not in ("none", "sudo-noninteractive"):
        raise BridgeError("bridge privilege mode is unsupported")
    upstream_raw = raw.get("upstream_path")
    sudo_raw = raw.get("sudo_path")
    if not isinstance(upstream_raw, str) or not isinstance(sudo_raw, (str, type(None))):
        raise BridgeError("bridge executable paths are invalid")
    require_root = privilege_mode == "sudo-noninteractive"
    upstream_path = _validate_trusted_file(
        Path(upstream_raw), executable=True, require_root_chain=require_root
    )
    sudo_path: Path | None = None
    if require_root:
        if not sudo_raw:
            raise BridgeError("sudo privilege mode requires a trusted sudo path")
        sudo_path = _validate_trusted_file(
            Path(sudo_raw), executable=True, require_root_chain=True
        )
    elif sudo_raw is not None:
        raise BridgeError("unprivileged mode must not configure sudo")
    upstream_sha256 = raw.get("upstream_sha256")
    if not isinstance(upstream_sha256, str) or not SHA256_RE.fullmatch(upstream_sha256):
        raise BridgeError("upstream executable digest is invalid")
    if _hash_file(upstream_path, MAX_UPSTREAM_BYTES) != upstream_sha256:
        raise BridgeError("upstream executable digest does not match")
    upstream_release = _bounded_label(raw.get("upstream_release"), "upstream release")
    readiness = raw.get("readiness_timeout_seconds")
    drain = raw.get("shutdown_drain_seconds")
    max_event = raw.get("max_event_bytes")
    if not isinstance(readiness, int) or isinstance(readiness, bool) or not 1 <= readiness <= 8:
        raise BridgeError("readiness timeout must be between 1 and 8 seconds")
    if not isinstance(drain, int) or isinstance(drain, bool) or not 0 <= drain <= 5:
        raise BridgeError("shutdown drain must be between 0 and 5 seconds")
    if not isinstance(max_event, int) or isinstance(max_event, bool) or not 1 <= max_event <= MAX_EVENT_BYTES:
        raise BridgeError("event byte limit is invalid")
    return BridgeConfig(
        upstream_path=upstream_path,
        upstream_sha256=upstream_sha256,
        upstream_release=upstream_release,
        privilege_mode=privilege_mode,
        sudo_path=sudo_path,
        readiness_timeout_seconds=readiness,
        shutdown_drain_seconds=drain,
        max_event_bytes=max_event,
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
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return False
    return any(line == f"0::{relative}" for line in lines)


def _positive_int(value: object, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise BridgeError("AgentSight numeric field is invalid")
    return value


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
        self.allowed_pids: set[int] = {args.target_pid}
        self.allowed_pids_lock = threading.Lock()
        self.tracker_stop = threading.Event()
        self.tracker_failed = False
        self.stop_requested = False
        self.child: subprocess.Popen[bytes] | None = None
        self.shutdown_timer: threading.Timer | None = None
        self.ready = False
        self.saw_end_anchor = False
        self.events = 0
        self.probe_hits = 0
        self.drops = 0
        self.diagnostic_bytes = 0
        self.stderr_problem = False
        self.stdout_overflow = False
        self.gap_once_reasons: set[str] = set()

    def gap(self, reason: str, occurrences: int = 1, *, once: bool = False) -> None:
        if once and reason in self.gap_once_reasons:
            return
        if once:
            self.gap_once_reasons.add(reason)
        occurrences = max(1, min(occurrences, MAX_OCCURRENCES))
        self.drops = min(self.drops + occurrences, MAX_OCCURRENCES)
        _emit(
            {
                "type": "gap",
                "schema_version": PROTOCOL_VERSION,
                "reason": reason,
                "occurrences": occurrences,
            },
            self.output,
        )

    def _signal_child_stop(self) -> None:
        child = self.child
        if child is not None and child.poll() is None:
            try:
                os.kill(child.pid, signal.SIGINT)
            except ProcessLookupError:
                pass

    def request_stop(self, _signum: int, _frame: object) -> None:
        self.stop_requested = True
        if self.child is None or self.child.poll() is not None:
            return
        if self.shutdown_timer is None:
            self.shutdown_timer = threading.Timer(
                self.config.shutdown_drain_seconds, self._signal_child_stop
            )
            self.shutdown_timer.daemon = True
            self.shutdown_timer.start()

    def _track_cgroup_members(self) -> None:
        path = self.args.target_cgroup / "cgroup.procs"
        while not self.tracker_stop.is_set():
            try:
                values = path.read_text(encoding="ascii").splitlines()
                pids = {
                    int(value)
                    for value in values
                    if value.isascii() and value.isdecimal() and len(value) <= 10
                }
                if len(pids) != len(values) or any(not 1 <= pid <= (1 << 31) - 1 for pid in pids):
                    raise ValueError("invalid PID in target cgroup")
                with self.allowed_pids_lock:
                    new = pids.difference(self.allowed_pids)
                    if len(self.allowed_pids) + len(new) > MAX_TRACKED_PIDS:
                        raise ValueError("target cgroup PID history exceeds its limit")
                    self.allowed_pids.update(new)
            except (OSError, UnicodeError, ValueError):
                self.tracker_failed = True
                return
            self.tracker_stop.wait(CGROUP_SAMPLE_SECONDS)

    def _event_pid_is_bound(self, pid: int) -> bool:
        with self.allowed_pids_lock:
            if pid in self.allowed_pids:
                return True
        if not _pid_in_cgroup(pid, self.args.cgroup_relative):
            return False
        with self.allowed_pids_lock:
            if len(self.allowed_pids) >= MAX_TRACKED_PIDS:
                return False
            self.allowed_pids.add(pid)
        return True

    def _emit_ready(self) -> None:
        if self.ready:
            self.gap("duplicate_start_anchor", once=True)
            return
        self.ready = True
        _emit(
            {
                "type": "ready",
                "schema_version": PROTOCOL_VERSION,
                "helper": "agentsight-bridge",
                "helper_version": HELPER_VERSION,
                "upstream_name": "agentsight",
                "upstream_version": self.config.upstream_release,
                "capabilities": [
                    "process_lifecycle",
                    "file_activity",
                    "network_activity",
                    "cgroup_filter",
                    "aggregate_overflow_reporting",
                ],
                "target_pid": self.args.target_pid,
                "target_executable_sha256": self.args.target_executable_sha256,
                "target_cgroup": str(self.args.target_cgroup),
                "filter_scope": "cgroup",
            },
            self.output,
        )
        # AgentSight v1.0.25 increments no counter when process.bpf.c ring-buffer
        # reservation fails.  Never turn absence of a warning into completeness.
        self.gap("upstream_ring_buffer_loss_unobservable", once=True)

    def _classify(self, data: dict[str, object]) -> tuple[str, str, str | None]:
        event = data.get("event")
        if event in ("EXEC", "EXIT"):
            return "agentsight_process_lifecycle", "process", None
        if event == "BASH_READLINE":
            return "agentsight_process_input", "process", None
        if event == "FILE_OPEN":
            if "rate_limit_warning" in data:
                self.gap("upstream_file_rate_limit", once=True)
            return "agentsight_file_activity", "filesystem", None
        if event == "SUMMARY":
            summary_type = data.get("type")
            if summary_type in FILE_SUMMARY_TYPES:
                return "agentsight_file_activity", "filesystem", None
            if summary_type in NETWORK_SUMMARY_TYPES:
                return "agentsight_network_activity", "network", str(summary_type).lower()
            if summary_type in PROCESS_SUMMARY_TYPES:
                return "agentsight_process_coordination", "process", None
            if summary_type in MEMORY_SUMMARY_TYPES:
                return "agentsight_memory_activity", "memory", None
        if event == "WARNING":
            warning_type = data.get("type")
            if warning_type == "AGG_MAP_OVERFLOW":
                count = _positive_int(data.get("overflow_count"), MAX_OCCURRENCES)
                self.gap("upstream_aggregate_map_overflow", count)
            elif warning_type == "FILE_RATE_LIMIT":
                self.gap("upstream_file_rate_limit", once=True)
            else:
                self.gap("upstream_warning", once=True)
            return "agentsight_diagnostic", "diagnostic", None
        self.gap("upstream_unknown_event", once=True)
        return "agentsight_diagnostic", "diagnostic", None

    def process_line(self, raw: bytes) -> None:
        stripped = raw.strip()
        if not stripped:
            return
        try:
            text = stripped.decode("utf-8")
        except UnicodeDecodeError:
            self.gap("upstream_event_parse_failed", once=True)
            return
        if text in KNOWN_BANNER_LINES or (text and set(text) in ({"-"}, {"="})):
            return
        try:
            outer = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            self.gap("upstream_event_parse_failed", once=True)
            return
        if not isinstance(outer, dict) or set(outer) != {"timestamp", "source", "pid", "comm", "data"}:
            self.gap("upstream_event_schema_changed", once=True)
            return
        data = outer.get("data")
        if not isinstance(data, dict):
            self.gap("upstream_event_schema_changed", once=True)
            return
        if outer.get("source") == "diagnostic" and data.get("event") == "CLOCK_SYNC":
            if outer.get("pid") != 0 or outer.get("comm") != "process":
                self.gap("upstream_event_schema_changed", once=True)
                return
            phase = data.get("phase")
            if phase == "start":
                self._emit_ready()
            elif phase == "end":
                if not self.ready:
                    self.gap("upstream_end_anchor_before_start", once=True)
                else:
                    self.saw_end_anchor = True
            else:
                self.gap("upstream_clock_anchor_invalid", once=True)
            return
        if not self.ready:
            raise BridgeError("AgentSight emitted evidence before its start anchor")
        if outer.get("source") == "diagnostic" and data.get("type") in (
            "runner_error",
            "runner_parse_error",
        ):
            self.gap("upstream_runner_error", once=True)
            return
        if data.get("event") == "WARNING":
            try:
                self._classify(data)
            except BridgeError:
                self.gap("upstream_warning_counter_invalid", once=True)
            self.probe_hits += 1
            return
        if outer.get("source") != "process":
            self.gap("upstream_event_schema_changed", once=True)
            return
        try:
            pid = _positive_int(outer.get("pid"), (1 << 31) - 1)
        except BridgeError:
            self.gap("upstream_event_schema_changed", once=True)
            return
        if data.get("pid") != pid or data.get("comm") != outer.get("comm"):
            self.gap("upstream_event_schema_changed", once=True)
            return
        if not self._event_pid_is_bound(pid):
            self.gap("upstream_event_outside_target_cgroup", once=True)
            return
        if self.events >= MAX_EVENTS:
            self.gap("upstream_event_count_limit_exceeded", once=True)
            return
        try:
            event_name, protocol, direction = self._classify(data)
        except BridgeError:
            self.gap("upstream_event_schema_changed", once=True)
            return
        digest = hashlib.sha256(stripped).hexdigest()
        record: dict[str, object] = {
            "type": "evidence",
            "schema_version": PROTOCOL_VERSION,
            "event": event_name,
            "pid": pid,
            "protocol": protocol,
            "media_type": "application/vnd.agentsight.event+json",
            "payload_base64": base64.b64encode(stripped).decode("ascii"),
            "payload_sha256": "sha256:" + digest,
            "confidence": 1.0,
        }
        if direction is not None:
            record["direction"] = direction
            record["connection_id"] = "agentsight-" + digest[:32]
        _emit(record, self.output)
        self.events += 1
        self.probe_hits += 1

    def _read_stdout(self, stream: BinaryIO, output: Queue[bytes | None]) -> None:
        try:
            while True:
                line = stream.readline(self.config.max_event_bytes + 2)
                if not line:
                    break
                if len(line) > self.config.max_event_bytes or not line.endswith(b"\n"):
                    self.stdout_overflow = True
                    while line and not line.endswith(b"\n"):
                        line = stream.readline(self.config.max_event_bytes + 2)
                    continue
                output.put(line)
        finally:
            output.put(None)

    def _read_stderr(self, stream: BinaryIO) -> None:
        problem_markers = (b"error", b"failed", b"overflow", b"dropped", b"skipping non-json")
        overlap = b""
        overlap_bytes = max(map(len, problem_markers)) - 1
        while chunk := stream.read(4096):
            self.diagnostic_bytes += len(chunk)
            lowered = overlap + chunk.lower()
            if any(marker in lowered for marker in problem_markers):
                self.stderr_problem = True
            overlap = lowered[-overlap_bytes:]

    def _command(self) -> list[str]:
        command: list[str] = []
        if self.config.privilege_mode == "sudo-noninteractive":
            assert self.config.sudo_path is not None
            command.extend([str(self.config.sudo_path), "-n", "--"])
        command.extend(
            [
                str(self.config.upstream_path),
                "debug",
                "process",
                "--",
                "--cgroup-filter",
                str(self.args.target_cgroup),
                "--cgroup-filter-children",
                "--trace-all",
                "-m",
                "1",
                "--seed-pid",
                str(self.args.target_pid),
            ]
        )
        return command

    def run(self) -> int:
        try:
            self.child = subprocess.Popen(
                self._command(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                close_fds=True,
            )
        except OSError as exc:
            raise BridgeError("AgentSight could not be started") from exc
        assert self.child.stdout is not None and self.child.stderr is not None
        if self.stop_requested:
            self._signal_child_stop()
        lines: Queue[bytes | None] = Queue(maxsize=UPSTREAM_QUEUE_RECORDS)
        stdout_thread = threading.Thread(
            target=self._read_stdout, args=(self.child.stdout, lines), daemon=True
        )
        stderr_thread = threading.Thread(
            target=self._read_stderr, args=(self.child.stderr,), daemon=True
        )
        tracker_thread = threading.Thread(target=self._track_cgroup_members, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        tracker_thread.start()
        deadline = time.monotonic() + self.config.readiness_timeout_seconds
        try:
            while True:
                wait_seconds = 0.2
                if not self.ready:
                    wait_seconds = max(0.0, min(wait_seconds, deadline - time.monotonic()))
                try:
                    raw = lines.get(timeout=wait_seconds)
                except Empty:
                    raw = b""
                if raw is None:
                    break
                if raw:
                    self.process_line(raw)
                if not self.ready and time.monotonic() >= deadline:
                    self._signal_child_stop()
                    raise BridgeError("AgentSight readiness deadline expired")
                if not raw and self.child.poll() is not None and not stdout_thread.is_alive():
                    break
            code = self.child.wait()
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            self.tracker_stop.set()
            tracker_thread.join(timeout=2)
            if not self.ready:
                raise BridgeError("AgentSight exited before its start anchor")
            if self.tracker_failed or tracker_thread.is_alive():
                self.gap("cgroup_membership_tracking_failed", once=True)
            if self.stdout_overflow:
                self.gap("upstream_line_limit_exceeded", once=True)
            if self.diagnostic_bytes > MAX_DIAGNOSTIC_BYTES:
                self.gap("upstream_stderr_limit_exceeded", once=True)
            if self.stderr_problem:
                self.gap("upstream_diagnostic_reported_failure", once=True)
            if not self.saw_end_anchor:
                self.gap("upstream_end_anchor_missing", once=True)
            if self.probe_hits == 0:
                self.gap("no_probe_hits", once=True)
            if code != 0:
                self.gap("upstream_nonzero_exit", once=True)
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
            return 0 if self.stop_requested and code == 0 else 1
        finally:
            if self.shutdown_timer is not None:
                self.shutdown_timer.cancel()
            self.tracker_stop.set()
            if self.child.poll() is None:
                self._signal_child_stop()
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            tracker_thread.join(timeout=2)
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
        raise BridgeError("AgentSight bridge requires iorec cgroup filtering")
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
            config_path = Path(sys.argv[0]).resolve().with_name("agentsight-bridge.json")
        config = load_config(config_path.resolve(strict=True))
        bridge = Bridge(args, config)
        signal.signal(signal.SIGTERM, bridge.request_stop)
        signal.signal(signal.SIGINT, bridge.request_stop)
        return bridge.run()
    except (BridgeError, OSError) as exc:
        print(f"agentsight bridge: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
