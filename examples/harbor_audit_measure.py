#!/usr/bin/env python3
"""Linux CLI observer shared by recorder-on and recorder-off Harbor runs.

Never stores argv, environment, stdin or output. Child stdio is inherited.
wait4 accounts for the waited child and descendants whose usage it collected;
max RSS is the largest individual process peak, NOT a simultaneous tree total.
Detached/unwaited descendants and the observer's own CPU are outside this scope.
Child launch costs and pre-exec inherited memory may contribute to wait4 usage.
This is a measurement aid, not an attestation against a hostile same-UID agent.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

RESOURCE_SCOPE = "linux_wait4_waited_child_and_accounted_descendants_not_tree_total"
WALL_SCOPE = "command_launch_through_reap_including_recorder_startup_flush_not_install_or_verifier"


def publish(directory: Path, name: str, value):
    """Private atomic publication without replacing an existing artifact."""
    temporary = directory / (".next-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, sort_keys=True, allow_nan=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.link(temporary, directory / name, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def measure(output: Path, mode: str, command: list[str]) -> int:
    if sys.platform != "linux" or mode not in ("on", "off") or not command:
        raise ValueError("unsupported_measurement")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = output.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("measurement_directory_not_private")
    invocation = uuid.uuid4().hex
    directory = output / invocation
    directory.mkdir(mode=0o700)
    header = {"schema_version": 1, "invocation_id": invocation, "recording_mode": mode,
              "resource_scope": RESOURCE_SCOPE, "wall_scope": WALL_SCOPE,
              "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "declared_network_mode": "recorder_task_netns_transparent_proxy" if mode == "on" else "container_native",
              "observer_python_version": ".".join(map(str, sys.version_info[:3]))}
    # A surviving start without a result means interrupted/unknown, not zero cost.
    publish(directory, "started.json", {**header, "measurement_status": "started"})
    child = None
    received = []
    pending = []
    signal_count = 0

    def forward(signum, _frame):
        nonlocal signal_count
        signal_count += 1
        if len(received) < 16:
            received.append(signum)
        if child is None and len(pending) < 16:
            pending.append(signum)
        if child is not None and child.returncode is None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    watched = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)
    previous = {sig: signal.signal(sig, forward) for sig in watched}
    started = time.monotonic()
    try:
        try:
            child = subprocess.Popen(command, start_new_session=True)
        except OSError as error:
            # Fixed numeric error only: OSError text can echo secret arguments.
            code = 127 if isinstance(error, FileNotFoundError) else 126
            publish(directory, "result.json", {**header, "measurement_status": "launch_failed",
                    "exit_code": code, "launch_errno": error.errno})
            return code
        for sig in pending:
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
        result = {**header, "measurement_status": "completed", "exit_code": child.returncode,
                  "terminating_signal": -child.returncode if child.returncode < 0 else None,
                  "wall_seconds": time.monotonic() - started,
                  "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                  "max_rss_kib": usage.ru_maxrss,
                  "observer_signal_count": signal_count, "observer_signals": received}
        try:
            publish(directory, "result.json", result)
        except OSError:
            # Keep the target's exit semantics. The workflow rejects missing results.
            print("iorec_measurement_publish_failed", file=sys.stderr)
        return child.returncode
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--mode", choices=("on", "off"), required=True)
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        code = measure(args.output, args.mode, command)
    except Exception:
        print("iorec_measurement_failed", file=sys.stderr)
        return 125
    if code < 0:
        # Preserve signal termination, not just its shell-style 128+N encoding.
        if -code != signal.SIGKILL:
            signal.signal(-code, signal.SIG_DFL)
        os.kill(os.getpid(), -code)
    return code


def read_trial_measurements(trial: Path, mode: str):
    """Validate a bounded set of complete CLI observations.

    Harbor downloads these target-owned files. Shape/hash validation does not
    make them independent security evidence against the target.
    """
    root = trial / "agent/iorec-measurements"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("measurement_missing")
    # Bound enumeration even for hostile/unexpected agent output.
    entries = []
    with os.scandir(root) as children:
        for entry in children:
            entries.append(entry.name)
            if len(entries) > 16:
                raise ValueError("measurement_count_limit_exceeded")
    entries.sort()
    if not entries or any(not re.fullmatch(r"[0-9a-f]{32}", entry) for entry in entries):
        raise ValueError("invalid_measurement_set")
    return [_read_measurement_directory(root / entry, mode) for entry in entries]


def read_trial_measurement(trial: Path, mode: str):
    """Compatibility helper for workflows that require exactly one CLI call."""
    root = trial / "agent/iorec-measurements"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("measurement_missing")
    with os.scandir(root) as children:
        try:
            next(children)
        except StopIteration:
            raise ValueError("expected_exactly_one_measurement") from None
        try:
            next(children)
        except StopIteration:
            pass
        else:
            raise ValueError("expected_exactly_one_measurement")
    measurements = read_trial_measurements(trial, mode)
    return measurements[0]


def _read_measurement_directory(directory: Path, mode: str):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid_measurement_directory")

    def read(name):
        fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as src:
            if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                raise ValueError("measurement_not_regular")
            raw = src.read(8193)
        if len(raw) > 8192:
            raise ValueError("measurement_too_large")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid_measurement")
        return value, hashlib.sha256(raw).hexdigest()

    start, start_hash = read("started.json")
    result, result_hash = read("result.json")
    header_keys = {"schema_version", "invocation_id", "recording_mode", "resource_scope", "wall_scope",
                   "started_at", "declared_network_mode", "observer_python_version"}
    metric_keys = {"exit_code", "terminating_signal", "wall_seconds", "user_cpu_seconds", "system_cpu_seconds",
                   "max_rss_kib", "observer_signal_count", "observer_signals"}
    if (set(start) != header_keys | {"measurement_status"}
            or set(result) != header_keys | metric_keys | {"measurement_status"}
            or start.get("measurement_status") != "started" or result.get("measurement_status") != "completed"
            or any(start[k] != result[k] for k in header_keys)):
        raise ValueError("measurement_incomplete_or_changed")
    if (type(result["schema_version"]) is not int or result["schema_version"] != 1
            or result["invocation_id"] != directory.name or mode not in ("on", "off")
            or result["recording_mode"] != mode or result["resource_scope"] != RESOURCE_SCOPE
            or result["wall_scope"] != WALL_SCOPE
            or result["declared_network_mode"] != ("recorder_task_netns_transparent_proxy" if mode == "on" else "container_native")
            or not isinstance(result["observer_python_version"], str)
            or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", result["observer_python_version"])):
        raise ValueError("measurement_scope_mismatch")
    timestamp = result["started_at"]
    if not isinstance(timestamp, str) or len(timestamp) > 40 or dt.datetime.fromisoformat(timestamp).utcoffset() != dt.timedelta(0):
        raise ValueError("invalid_measurement_time")
    for field in ("wall_seconds", "user_cpu_seconds", "system_cpu_seconds"):
        value = result[field]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1e12:
            raise ValueError("invalid_measurement_metric")
    for field in ("max_rss_kib", "observer_signal_count"):
        if type(result[field]) is not int or not 0 <= result[field] <= 2**63 - 1:
            raise ValueError("invalid_measurement_metric")
    code = result["exit_code"]
    if type(code) is not int or not -64 <= code <= 255:
        raise ValueError("invalid_measurement_exit")
    terminating = result["terminating_signal"]
    if terminating != (-code if code < 0 else None) or (terminating is not None and type(terminating) is not int):
        raise ValueError("invalid_measurement_exit")
    received = result["observer_signals"]
    if (not isinstance(received, list) or len(received) > 16 or len(received) > result["observer_signal_count"]
            or any(type(sig) is not int or sig not in (1, 2, 3, 15) for sig in received)):
        raise ValueError("invalid_measurement_signals")
    return {**result, "started_sha256": start_hash, "result_sha256": result_hash,
            "provenance": "target_owned_observer_output_not_independent_attestation"}


if __name__ == "__main__":
    sys.exit(main())
