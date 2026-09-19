#!/usr/bin/env python3
"""Qualify twenty persistent iorec collectors against the platform.

This harness intentionally drives the shipped recorder and collector binaries.
Each collector owns one long-running encrypted model stream.  The harness stops
the platform API, proves every local event log continues to advance while it is
unavailable, restores it, restarts all collectors, restarts the pipeline workers,
reconciles every local segment with the platform, and finally proves one
irreversible remote-to-local deletion propagation.

Short executions are useful calibrations.  A report is release-qualifying only
when all checks pass with exactly 20 collectors for at least 18,000 measured
seconds and every required fault was observed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

import perf_harness
import websocket_fixture
import websocket_soak_validation


SCHEMA_VERSION = 1
QUALIFYING_COLLECTORS = 20
QUALIFYING_SECONDS = 18_000.0
MAX_COLLECTORS = 100
MAX_DURATION_SECONDS = 7 * 24 * 60 * 60
MAX_REQUEST_INTERVAL_SECONDS = 30 * 60
MAX_DRAIN_SECONDS = 60 * 60
MAX_SEGMENT_SECONDS = 60 * 60
MAX_UNIX_SOCKET_PATH_BYTES = 107
MAX_API_RATE_LIMIT_RETRIES = 60
MAX_API_RETRY_AFTER_SECONDS = 60
PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")


@dataclass
class ManagedProcess:
    index: int
    kind: str
    process: subprocess.Popen[bytes]
    log_file: Any
    log_path: pathlib.Path


@dataclass
class FaultEvidence:
    platform_outage_started: str | None = None
    platform_unavailable_observed: bool = False
    outage_pre_events: dict[str, int] = field(default_factory=dict)
    outage_post_events: dict[str, int] = field(default_factory=dict)
    local_recording_advanced: dict[str, bool] = field(default_factory=dict)
    platform_restored_at: str | None = None
    collector_restart_at: str | None = None
    collector_ids_before: dict[str, str] = field(default_factory=dict)
    collector_ids_after: dict[str, str] = field(default_factory=dict)
    collector_identity_stable: dict[str, bool] = field(default_factory=dict)
    worker_restart_at: str | None = None
    worker_restart_passed: bool = False


def positive_int(raw: str) -> int:
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def positive_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return value


def nonnegative_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("must be a finite nonnegative number")
    return value


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the fault-injected iorec connected-recorder soak"
    )
    parser.add_argument("--iorec", type=pathlib.Path, default=pathlib.Path("target/release/iorec"))
    parser.add_argument("--api", required=True)
    parser.add_argument("--project-token-file", required=True, type=pathlib.Path)
    parser.add_argument("--admin-token-file", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--work-dir", required=True, type=pathlib.Path)
    parser.add_argument("--duration-seconds", required=True, type=positive_float)
    parser.add_argument("--collectors", type=positive_int, default=QUALIFYING_COLLECTORS)
    parser.add_argument("--workload", choices=("http-sse", "mixed-websocket"), default="http-sse")
    parser.add_argument("--node", type=pathlib.Path, default=pathlib.Path("/usr/bin/node"))
    parser.add_argument(
        "--request-interval-seconds", type=positive_float, default=60.0
    )
    parser.add_argument(
        "--segment-seconds", type=positive_int, default=300,
        help="collector active-run rolling interval",
    )
    parser.add_argument("--drain-seconds", type=positive_float, default=900.0)
    parser.add_argument("--outage-at-seconds", type=nonnegative_float)
    parser.add_argument("--outage-seconds", type=positive_float)
    parser.add_argument("--collector-restart-at-seconds", type=nonnegative_float)
    parser.add_argument("--worker-restart-at-seconds", type=nonnegative_float)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument(
        "--compose-file", action="append", required=True, type=pathlib.Path
    )
    return parser.parse_args()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_private_file(path: pathlib.Path, label: str) -> str:
    path = pathlib.Path(os.path.abspath(path.expanduser()))
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if info.st_mode & 0o077:
        raise PermissionError(f"{label} must not be accessible by group or other users")
    if info.st_size <= 0 or info.st_size > 2048:
        raise ValueError(f"{label} has an invalid size")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(character.isspace() for character in value):
        raise ValueError(f"{label} must contain one non-empty token")
    return value


def validate_api(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme != "http" or not parsed.hostname or parsed.port is None:
        raise ValueError("qualification API must be an explicit http://host:port URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise ValueError("qualification API host must be a literal loopback address") from error
    if not address.is_loopback:
        raise ValueError("qualification refuses to disrupt a non-loopback platform")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("qualification API must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("qualification API must not contain a path")
    return raw.rstrip("/")


def resolve_file(path: pathlib.Path, label: str, executable: bool = False) -> pathlib.Path:
    absolute = pathlib.Path(os.path.abspath(path.expanduser()))
    info = absolute.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file: {absolute}")
    resolved = absolute.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {resolved}")
    if executable and not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} is not executable: {resolved}")
    return resolved


def prepare_paths(args: argparse.Namespace) -> tuple[pathlib.Path, pathlib.Path]:
    work_dir = args.work_dir.expanduser().resolve()
    if work_dir.exists() or work_dir.is_symlink():
        raise FileExistsError(f"refusing a pre-existing work directory: {work_dir}")
    work_dir.mkdir(mode=0o700, parents=True)
    work_dir.chmod(0o700)
    output_parent = args.output.expanduser().parent.resolve(strict=True)
    output = output_parent / args.output.name
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite report: {output}")
    return work_dir, output


def derive_schedule(args: argparse.Namespace) -> dict[str, float]:
    duration = args.duration_seconds
    outage_at = args.outage_at_seconds
    if outage_at is None:
        outage_at = duration * 0.20
    outage_seconds = args.outage_seconds
    if outage_seconds is None:
        outage_seconds = max(args.request_interval_seconds * 2.5, duration * 0.05)
    collector_restart = args.collector_restart_at_seconds
    if collector_restart is None:
        collector_restart = duration * 0.50
    worker_restart = args.worker_restart_at_seconds
    if worker_restart is None:
        worker_restart = duration * 0.70
    schedule = {
        "outage_at_seconds": float(outage_at),
        "outage_seconds": float(outage_seconds),
        "collector_restart_at_seconds": float(collector_restart),
        "worker_restart_at_seconds": float(worker_restart),
    }
    outage_end = schedule["outage_at_seconds"] + schedule["outage_seconds"]
    if schedule["outage_at_seconds"] <= 0 or outage_end >= duration:
        raise ValueError("platform outage must start after zero and end before the soak")
    if not outage_end < schedule["collector_restart_at_seconds"] < duration:
        raise ValueError("collector restart must occur after platform restoration and before the end")
    if not schedule["collector_restart_at_seconds"] < schedule["worker_restart_at_seconds"] < duration:
        raise ValueError("worker restart must occur after collector restart and before the end")
    if schedule["outage_seconds"] < args.request_interval_seconds:
        raise ValueError("outage must span at least one request interval")
    return schedule


def validate_limits(args: argparse.Namespace) -> None:
    if args.collectors > MAX_COLLECTORS:
        raise ValueError(f"collector count exceeds {MAX_COLLECTORS}")
    if args.duration_seconds > MAX_DURATION_SECONDS:
        raise ValueError("duration exceeds seven days")
    if args.request_interval_seconds > MAX_REQUEST_INTERVAL_SECONDS:
        raise ValueError("request interval exceeds thirty minutes")
    if args.drain_seconds > MAX_DRAIN_SECONDS:
        raise ValueError("drain timeout exceeds one hour")
    if args.segment_seconds > MAX_SEGMENT_SECONDS:
        raise ValueError("segment interval exceeds one hour")
    if not PROJECT_RE.fullmatch(args.compose_project):
        raise ValueError("compose project has an invalid name")
    if args.workload == "mixed-websocket":
        if args.collectors < 2 or math.ceil(args.duration_seconds / args.request_interval_seconds) > 1000:
            raise ValueError("mixed workload requires at least two collectors and at most 1000 calls per collector")


def urlopen_with_rate_limit_retry(
    request: urllib.request.Request, timeout: float
) -> Any:
    """Open one API request while respecting the server's bounded 429 delay."""
    for attempt in range(MAX_API_RATE_LIMIT_RETRIES + 1):
        try:
            return urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == MAX_API_RATE_LIMIT_RETRIES:
                raise
            raw_delay = error.headers.get("Retry-After", "1")
            try:
                delay = int(raw_delay)
            except (TypeError, ValueError):
                delay = 1
            delay = min(max(delay, 1), MAX_API_RETRY_AFTER_SECONDS)
            error.close()
            time.sleep(delay)
    raise AssertionError("unreachable rate-limit retry loop")


def api_json(api: str, path: str, token: str, timeout: float = 10.0) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{api}{path}", headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    with urlopen_with_rate_limit_retry(request, timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected API status {response.status} for {path}")
        if int(response.headers.get("Content-Length", "0") or 0) > 64 * 1024 * 1024:
            raise RuntimeError(f"API response is too large for {path}")
        body = response.read(64 * 1024 * 1024 + 1)
    if len(body) > 64 * 1024 * 1024:
        raise RuntimeError(f"API response is too large for {path}")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"API response is not an object for {path}")
    return parsed


def api_mutation_json(
    api: str,
    path: str,
    token: str,
    method: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{api}{path}", data=body, headers=headers, method=method
    )
    with urlopen_with_rate_limit_retry(request, timeout) as response:
        if response.status not in {200, 201, 202}:
            raise RuntimeError(
                f"unexpected API status {response.status} for {method} {path}"
            )
        response_body = response.read(1024 * 1024 + 1)
    if len(response_body) > 1024 * 1024:
        raise RuntimeError(f"API response is too large for {method} {path}")
    parsed = json.loads(response_body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"API response is not an object for {method} {path}")
    return parsed


def api_available(api: str, token: str) -> bool:
    try:
        api_json(api, "/v1/overview", token, timeout=2.0)
        return True
    except (OSError, RuntimeError, ValueError, urllib.error.URLError):
        return False


def wait_until(
    description: str,
    timeout: float,
    predicate: Callable[[], bool],
    interval: float = 0.5,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as error:  # Transient state is expected while services restart.
            last_error = error
        time.sleep(interval)
    detail = f": {last_error}" if last_error is not None else ""
    raise TimeoutError(f"timed out waiting for {description}{detail}")


def compose_base(project: str, files: list[pathlib.Path]) -> list[str]:
    command = ["docker", "compose", "--project-name", project]
    for path in files:
        command.extend(["--file", str(path)])
    return command


def compose_action(
    base: list[str], action: str, services: list[str], timeout: float = 120.0
) -> None:
    if action not in {"stop", "start", "restart"}:
        raise ValueError("unsupported compose action")
    command = [*base, action]
    if action in {"stop", "restart"}:
        command.extend(["--timeout", "30"])
    command.extend(services)
    subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )


def parse_json_documents(raw: str) -> list[dict[str, Any]]:
    """Accept both Compose's JSON array and newline-delimited JSON formats."""
    stripped = raw.strip()
    if not stripped:
        return []
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        value = [json.loads(line) for line in stripped.splitlines() if line.strip()]
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("unexpected Docker Compose JSON output")
    return value


def compose_runtime_snapshot(
    base: list[str], compose_files: list[pathlib.Path]
) -> dict[str, Any]:
    """Capture only non-secret runtime identity and hardening evidence."""
    config = subprocess.run(
        [*base, "config"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120.0,
        check=True,
    ).stdout
    ps = subprocess.run(
        [*base, "ps", "--format", "json"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120.0,
        check=True,
    )
    rows = parse_json_documents(ps.stdout)
    container_ids = sorted(
        str(row.get("ID", "")) for row in rows if str(row.get("ID", ""))
    )
    if not container_ids:
        raise RuntimeError("Compose project has no running or created containers")
    inspected = subprocess.run(
        ["docker", "inspect", *container_ids],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120.0,
        check=True,
    )
    documents = json.loads(inspected.stdout)
    containers: list[dict[str, Any]] = []
    for document in documents:
        config_block = document.get("Config") or {}
        host = document.get("HostConfig") or {}
        state = document.get("State") or {}
        labels = config_block.get("Labels") or {}
        health = state.get("Health") or {}
        bindings: list[dict[str, Any]] = []
        for container_port, values in sorted((host.get("PortBindings") or {}).items()):
            hosts = sorted(
                {
                    str(value.get("HostIp", ""))
                    for value in (values or [])
                    if isinstance(value, dict)
                }
            )
            bindings.append({"container_port": container_port, "host_ips": hosts})
        log_config = host.get("LogConfig") or {}
        log_options = log_config.get("Config") or {}
        containers.append(
            {
                "name": str(document.get("Name", "")).lstrip("/"),
                "service": str(labels.get("com.docker.compose.service", "")),
                "container_id": str(document.get("Id", "")),
                "image_id": str(document.get("Image", "")),
                "image_reference": str(config_block.get("Image", "")),
                "state": str(state.get("Status", "")),
                "health": health.get("Status"),
                "user": str(config_block.get("User", "")),
                "read_only_rootfs": host.get("ReadonlyRootfs") is True,
                "cap_drop": sorted(str(value) for value in (host.get("CapDrop") or [])),
                "security_opt": sorted(
                    str(value) for value in (host.get("SecurityOpt") or [])
                ),
                "logging": {
                    "driver": str(log_config.get("Type", "")),
                    "max_size": log_options.get("max-size"),
                    "max_file": log_options.get("max-file"),
                },
                "port_bindings": bindings,
            }
        )
    containers.sort(key=lambda item: (item["service"], item["name"]))
    return {
        "captured_at": utc_now(),
        "compose_config_sha256": f"sha256:{hashlib.sha256(config).hexdigest()}",
        "compose_files": [
            {
                "path": str(path),
                "sha256": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
            }
            for path in compose_files
        ],
        "containers": containers,
    }


def runtime_provenance(
    start: dict[str, Any], end: dict[str, Any]
) -> dict[str, Any]:
    expected_counts = {
        "platform-api": 1,
        "pipeline-worker": 2,
        "web-console": 1,
        "postgres": 1,
    }

    def by_service(snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for container in snapshot["containers"]:
            result.setdefault(container["service"], []).append(container)
        return result

    def service_counts(snapshot: dict[str, Any]) -> dict[str, int]:
        grouped = by_service(snapshot)
        return {service: len(grouped.get(service, [])) for service in expected_counts}

    def image_sets(snapshot: dict[str, Any]) -> dict[str, list[str]]:
        grouped = by_service(snapshot)
        return {
            service: sorted({item["image_id"] for item in grouped.get(service, [])})
            for service in expected_counts
        }

    def apps_hardened(snapshot: dict[str, Any]) -> bool:
        application_services = {"platform-api", "pipeline-worker", "web-console"}
        apps = [
            item
            for item in snapshot["containers"]
            if item["service"] in application_services
        ]
        return bool(apps) and all(
            item["user"] not in {"", "0", "0:0", "root", "root:root"}
            and item["read_only_rootfs"] is True
            and item["cap_drop"] == ["ALL"]
            and "no-new-privileges:true" in item["security_opt"]
            and item["logging"]
            == {"driver": "json-file", "max_size": "20m", "max_file": "5"}
            for item in apps
        )

    def published_ports_are_loopback(snapshot: dict[str, Any]) -> bool:
        grouped = by_service(snapshot)
        for service in ("platform-api", "web-console"):
            containers = grouped.get(service, [])
            if len(containers) != 1 or not containers[0]["port_bindings"]:
                return False
            host_ips = [
                host_ip
                for binding in containers[0]["port_bindings"]
                for host_ip in binding["host_ips"]
            ]
            if not host_ips or not all(
                ipaddress.ip_address(host_ip).is_loopback for host_ip in host_ips
            ):
                return False
        return True

    start_counts = service_counts(start)
    end_counts = service_counts(end)
    start_images = image_sets(start)
    end_images = image_sets(end)
    start_grouped = by_service(start)
    end_grouped = by_service(end)
    checks = {
        "expected_service_counts_at_start": start_counts == expected_counts,
        "expected_service_counts_at_end": end_counts == expected_counts,
        "all_containers_running_at_start": all(
            item["state"] == "running" for item in start["containers"]
        ),
        "all_containers_running_at_end": all(
            item["state"] == "running" for item in end["containers"]
        ),
        "image_ids_unchanged": start_images == end_images
        and all(len(values) == 1 and values[0] for values in start_images.values()),
        "compose_configuration_unchanged": start["compose_config_sha256"]
        == end["compose_config_sha256"],
        "compose_files_unchanged": start["compose_files"] == end["compose_files"],
        "application_hardening_at_start": apps_hardened(start),
        "application_hardening_at_end": apps_hardened(end),
        "published_ports_loopback_at_start": published_ports_are_loopback(start),
        "published_ports_loopback_at_end": published_ports_are_loopback(end),
        "web_healthy_at_start": len(start_grouped.get("web-console", [])) == 1
        and start_grouped["web-console"][0]["health"] == "healthy",
        "web_healthy_at_end": len(end_grouped.get("web-console", [])) == 1
        and end_grouped["web-console"][0]["health"] == "healthy",
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "image_ids": start_images,
        "start": start,
        "end": end,
    }


def open_private_log(path: pathlib.Path) -> Any:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb", buffering=0)


def workload_environment() -> dict[str, str]:
    # Compose credentials belong to the controller, never to the synthetic
    # agent. The collector receives its scoped credentials via explicit files.
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "TZ": "UTC"}


def start_collector(
    index: int,
    iorec: pathlib.Path,
    api: str,
    project_token_file: pathlib.Path,
    key_file: pathlib.Path,
    collector_dir: pathlib.Path,
    segment_seconds: int,
    generation: int,
) -> ManagedProcess:
    log_path = collector_dir / f"collector-{generation}.log"
    log_file = open_private_log(log_path)
    process = subprocess.Popen(
        [
            str(iorec),
            "collector",
            "--runs-dir",
            str(collector_dir / "runs"),
            "--api",
            api,
            "--token-file",
            str(project_token_file),
            "--key-file",
            str(key_file),
            "--allow-http",
            "--retry-seconds",
            "5",
            "--poll-seconds",
            "1",
            "--segment-max-seconds",
            str(segment_seconds),
            "--allow-remote-delete",
        ],
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=workload_environment(),
    )
    return ManagedProcess(index, "collector", process, log_file, log_path)


def start_recorder(
    index: int,
    iorec: pathlib.Path,
    fake_url: str,
    key_file: pathlib.Path,
    collector_dir: pathlib.Path,
    duration: float,
    request_interval: float,
    websocket: bool = False,
    node: pathlib.Path | None = None,
) -> ManagedProcess:
    log_path = collector_dir / "recorder.log"
    log_file = open_private_log(log_path)
    client = [
        sys.executable,
        str(pathlib.Path(perf_harness.__file__).resolve()),
        "_client",
        "--url-env",
        "IOREC_PROXY_URL",
        "--duration-seconds",
        str(duration),
        "--rate",
        str(1.0 / request_interval),
        "--concurrency",
        "1",
        "--payload-bytes",
        "1024",
        "--response-chunks",
        "3",
        "--response-chunk-bytes",
        "256",
        "--delay-ms",
        "5",
    ]
    if websocket:
        client = [str(node), str(pathlib.Path(__file__).with_name("websocket_soak_client.mjs").resolve()),
                  "--url-env", "IOREC_PROXY_URL", "--duration-seconds", str(duration),
                  "--interval-seconds", str(request_interval), "--calls-per-connection", "11"]
    command = [
        str(iorec),
        "run",
        "--runs-dir",
        str(collector_dir / "runs"),
        "--upstream",
        fake_url,
        "--provider",
        "none",
        "--adapter",
        "none",
        "--key-file",
        str(key_file),
        "--event-log-format",
        "zstd-blocks",
        "--",
        *client,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=workload_environment(),
    )
    return ManagedProcess(index, "recorder", process, log_file, log_path)


def stop_processes(processes: list[ManagedProcess], timeout: float = 30.0) -> None:
    """Stop independent process groups concurrently within one total deadline."""
    for managed in processes:
        if managed.process.poll() is None:
            try:
                os.killpg(managed.process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(managed.process.poll() is not None for managed in processes):
            break
        time.sleep(0.1)
    for managed in processes:
        if managed.process.poll() is None:
            try:
                os.killpg(managed.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    for managed in processes:
        try:
            managed.process.wait(timeout=10)
        finally:
            managed.log_file.close()


def close_completed(managed: ManagedProcess, timeout: float = 180.0) -> int:
    try:
        return_code = managed.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(managed.process.pid, signal.SIGTERM)
        try:
            return_code = managed.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(managed.process.pid, signal.SIGKILL)
            return_code = managed.process.wait(timeout=10)
    managed.log_file.close()
    return return_code


def check_live(processes: list[ManagedProcess], kind: str) -> None:
    exited = [(item.index, item.process.returncode) for item in processes if item.process.poll() is not None]
    if exited:
        raise RuntimeError(f"{kind} processes exited before their planned boundary: {exited[:10]}")


def collector_state(collector_dir: pathlib.Path) -> dict[str, Any]:
    path = collector_dir / "runs" / ".iorec-control" / "state.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("collector state is not an object")
    return data


def collector_ids(collector_dirs: list[pathlib.Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for index, path in enumerate(collector_dirs):
        value = collector_state(path).get("collector_id")
        if not isinstance(value, str) or not value:
            raise ValueError(f"collector {index} has no durable identity")
        result[str(index)] = value
    if len(set(result.values())) != len(result):
        raise ValueError("collector identities are not unique")
    return result


def only_run_dir(collector_dir: pathlib.Path) -> pathlib.Path:
    candidates = sorted(
        path
        for path in (collector_dir / "runs").glob("run-*")
        if path.is_dir() and not path.is_symlink()
    )
    if len(candidates) != 1:
        raise RuntimeError(f"expected one active run in {collector_dir}, found {len(candidates)}")
    return candidates[0]


def inspect_run(iorec: pathlib.Path, run_dir: pathlib.Path, key_file: pathlib.Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            str(iorec),
            "inspect",
            str(run_dir),
            "--json",
            "--key-file",
            str(key_file),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    data = json.loads(completed.stdout)
    if not isinstance(data, dict):
        raise ValueError("inspect output is not an object")
    return data


def event_snapshot(
    iorec: pathlib.Path, collector_dirs: list[pathlib.Path], key_file: pathlib.Path
) -> dict[str, int]:
    def inspect(index: int) -> tuple[str, int]:
        report = inspect_run(iorec, only_run_dir(collector_dirs[index]), key_file)
        return str(index), int(report["log"]["valid_events"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(collector_dirs))) as pool:
        return dict(pool.map(inspect, range(len(collector_dirs))))


def failure_diagnostics(error: Exception) -> dict[str, Any]:
    """Keep bounded failure identity without emitting command arguments or stderr."""
    if not isinstance(error, subprocess.CalledProcessError):
        return {"kind": type(error).__name__}
    stderr = error.stderr or b""
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", errors="replace")
    result: dict[str, Any] = {
        "kind": "subprocess_failure",
        "exit_code": error.returncode,
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    if isinstance(error.cmd, (list, tuple)) and len(error.cmd) > 1:
        subcommand = error.cmd[1]
        if subcommand in {"inspect", "verify", "collector", "run"}:
            result["iorec_subcommand"] = subcommand
    if b"storage I/O failed: No such file or directory (os error 2)" in stderr:
        result["category"] = "storage_entry_not_found"
    elif b"event log changed while it was being read" in stderr:
        result["category"] = "event_log_changed_during_read"
    else:
        result["category"] = "unclassified"
    return result


def parse_client_result(log_path: pathlib.Path) -> dict[str, Any]:
    if log_path.stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError(f"recorder log unexpectedly exceeds 16 MiB: {log_path}")
    result: dict[str, Any] | None = None
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and {"requests", "successes", "errors"} <= value.keys():
            result = value
    if result is None:
        raise ValueError(f"recorder log contains no client result: {log_path}")
    result.pop("_ttft_samples_ms", None)
    return result


def read_spool_chain(run_dir: pathlib.Path) -> list[dict[str, Any]]:
    spool = run_dir / ".upload"
    states: list[dict[str, Any]] = []
    for path in spool.glob("state-*.json"):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError(f"unsafe upload state: {path}")
        state_value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state_value, dict):
            raise ValueError(f"upload state is not an object: {path}")
        states.append(state_value)
    states.sort(key=lambda item: str(item.get("recording_id", "")))
    return states


def validate_spool_chain(
    states: list[dict[str, Any]], run_id: str, final_sequence: int
) -> dict[str, Any]:
    errors: list[str] = []
    expected = 1
    recording_ids: list[str] = []
    collector_ids_seen: set[str] = set()
    for segment, state_value in enumerate(states):
        recording_id = state_value.get("recording_id")
        expected_id = f"{run_id}#{segment:04d}"
        if recording_id != expected_id:
            errors.append(f"recording chain expected {expected_id}, found {recording_id}")
        recording_ids.append(str(recording_id))
        if state_value.get("run_id") != run_id:
            errors.append(f"segment {segment} has a different run ID")
        batches = state_value.get("batches")
        if not isinstance(batches, list) or not batches:
            errors.append(f"segment {segment} has no batch plan")
            continue
        for batch in batches:
            first = batch.get("first_seq")
            last = batch.get("last_seq")
            count = batch.get("event_count")
            if first != expected or not isinstance(last, int) or last < expected:
                errors.append(f"segment {segment} has a sequence gap at {expected}")
                break
            if count != last - first + 1:
                errors.append(f"segment {segment} has a batch event-count mismatch")
            expected = last + 1
        if state_value.get("acked_seq") != expected - 1:
            errors.append(f"segment {segment} was not acknowledged through its final batch")
        if state_value.get("sealed") is not True:
            errors.append(f"segment {segment} is not sealed")
        collector_id = state_value.get("collector_id")
        if isinstance(collector_id, str):
            collector_ids_seen.add(collector_id)
    if expected - 1 != final_sequence:
        errors.append(
            f"upload chain ends at {expected - 1}, local evidence ends at {final_sequence}"
        )
    if len(collector_ids_seen) != 1:
        errors.append("upload segments do not retain exactly one collector identity")
    return {
        "passed": not errors and bool(states),
        "errors": errors,
        "segments": len(states),
        "recording_ids": recording_ids,
        "final_sequence": expected - 1,
        "collector_ids": sorted(collector_ids_seen),
    }


def local_validation(
    iorec: pathlib.Path, run_dir: pathlib.Path, key_file: pathlib.Path
) -> dict[str, Any]:
    report = perf_harness.validate_run(iorec, run_dir, key_file)
    manifest = report["manifest"]
    report["passed"] = (
        manifest["status"] == "finished"
        and manifest["exit_code"] == 0
        and manifest["coverage"]["capture_drops"] == 0
        and manifest["counts"]["incomplete_attempts"] == 0
        and report["missing_blobs"] == 0
        and report["corrupt_blobs"] == 0
        and report["discarded_tail_bytes"] == 0
        and report["integrity_verifier"]["passed"] is True
    )
    return report


def verify_server_recording(api: str, token: str, recording_id: str) -> dict[str, Any]:
    escaped = urllib.parse.quote(recording_id, safe="")
    item = api_json(api, f"/v1/recordings/{escaped}", token, timeout=30.0)
    checks = {
        "state_sealed": item.get("state") == "sealed",
        "parsed_matches_durable": item.get("parsed_seq") == item.get("durable_seq"),
        "final_matches_durable": item.get("final_seq") == item.get("durable_seq"),
        "no_missing_blobs": item.get("missing_blobs") == [],
        "no_integrity_alerts": item.get("integrity_alerts") == [],
        "no_failed_jobs": item.get("failed_jobs") == 0,
        "no_active_jobs": item.get("active_jobs") == 0,
        "ui_archived": item.get("ui_state") == "archived",
    }
    return {
        "recording_id": recording_id,
        "sequence_base": item.get("sequence_base"),
        "durable_seq": item.get("durable_seq"),
        "checks": checks,
        "passed": all(checks.values()),
    }


def verify_deletion_propagation(
    api: str,
    token: str,
    run_dir: pathlib.Path,
    run_id: str,
    recording_id: str,
    timeout: float,
) -> dict[str, Any]:
    escaped_run = urllib.parse.quote(run_id, safe="")
    requested = api_mutation_json(
        api,
        f"/v1/capture-runs/{escaped_run}",
        token,
        "DELETE",
        {"confirmation": run_id, "reason": "connected_soak_end_to_end_gate"},
        timeout=30.0,
    )
    request_id = requested.get("id")
    if not isinstance(request_id, str) or not request_id:
        raise RuntimeError("deletion response has no request id")
    escaped_request = urllib.parse.quote(request_id, safe="")
    latest: dict[str, Any] = {}

    def converged() -> bool:
        nonlocal latest
        latest = api_json(api, f"/v1/deletions/{escaped_request}", token, timeout=15.0)
        return latest.get("state") == "done" and not run_dir.exists()

    wait_until("remote and local deletion propagation", timeout, converged, interval=1.0)
    escaped_recording = urllib.parse.quote(recording_id, safe="")
    tombstone = api_json(
        api, f"/v1/recordings/{escaped_recording}", token, timeout=30.0
    )
    attempts = api_json(
        api, f"/v1/attempts?capture_run_id={escaped_run}&limit=500", token, timeout=30.0
    )
    checks = {
        "request_completed": latest.get("state") == "done",
        "remote_deleted_at_recorded": isinstance(latest.get("remote_deleted_at"), str),
        "collector_request_recorded": isinstance(latest.get("collector_request_id"), str),
        "local_directory_removed": not run_dir.exists(),
        "recording_tombstone": tombstone.get("state") == "deleted",
        "raw_batches_removed": tombstone.get("batches") == [],
        "derived_attempts_removed": tombstone.get("attempt_count") == 0
        and attempts.get("items") == [],
        "sensitive_run_metadata_scrubbed": all(
            tombstone.get(field) is None
            for field in ("command", "cwd", "agent_kind", "agent_version")
        ),
    }
    return {
        "deletion_request_id": request_id,
        "capture_run_id": run_id,
        "recording_id": recording_id,
        "status": latest,
        "checks": checks,
        "passed": all(checks.values()),
    }
def overview_drained(
    api: str, token: str, baseline: dict[str, Any], expected_runs: int, expected_segments: int
) -> tuple[bool, dict[str, Any]]:
    current = api_json(api, "/v1/overview", token, timeout=15.0)
    checks = {
        "capture_run_delta": current.get("capture_runs", 0) - baseline.get("capture_runs", 0)
        == expected_runs,
        "recording_delta": current.get("recordings", 0) - baseline.get("recordings", 0)
        == expected_segments,
        "no_open_recordings": current.get("open_recordings") == baseline.get("open_recordings"),
        "no_active_jobs": current.get("active_jobs") == baseline.get("active_jobs"),
        "no_new_dead_jobs": current.get("dead_jobs") == baseline.get("dead_jobs"),
        "no_parse_lag": current.get("parse_lag_events") == baseline.get("parse_lag_events"),
        "collector_delta": current.get("online_collectors", 0)
        - baseline.get("online_collectors", 0)
        == expected_runs,
    }
    return all(checks.values()), {"values": current, "checks": checks}


def report_qualifies(report: dict[str, Any]) -> bool:
    return (
        report.get("passed") is True
        and report["configuration"]["collectors"] == QUALIFYING_COLLECTORS
        and report["measurement"]["minimum_recorder_seconds"] >= QUALIFYING_SECONDS
        and report["measurement"]["orchestrator_seconds"] >= QUALIFYING_SECONDS
        and report["faults"]["platform_unavailable_observed"] is True
        and all(report["faults"]["local_recording_advanced"].values())
        and len(report["faults"]["local_recording_advanced"]) == QUALIFYING_COLLECTORS
        and all(report["faults"]["collector_identity_stable"].values())
        and len(report["faults"]["collector_identity_stable"]) == QUALIFYING_COLLECTORS
        and report["faults"]["worker_restart_passed"] is True
        and report["checks"]["deletion_propagation"] is True
        and report["checks"]["platform_runtime_provenance"] is True
        and report.get("checks", {}).get("artifacts_unchanged", True) is True
        and (report["configuration"].get("workload") != "mixed-websocket" or (
            report["checks"].get("websocket_projection") is True
            and report["checks"].get("websocket_cross_segment_connections") is True
            and len(report.get("websocket_projections", [])) == QUALIFYING_COLLECTORS // 2))
    )


def artifact_snapshot(iorec: pathlib.Path, node: pathlib.Path | None) -> dict[str, str]:
    paths = [iorec, pathlib.Path(__file__).resolve(), pathlib.Path(perf_harness.__file__).resolve(),
             pathlib.Path(websocket_fixture.__file__).resolve(), pathlib.Path(websocket_soak_validation.__file__).resolve(),
             pathlib.Path(__file__).with_name("websocket_soak_client.mjs").resolve()]
    if node:
        paths.append(node)
    return {str(path): perf_harness.sha256_file(path) for path in paths}


def run(args: argparse.Namespace) -> dict[str, Any]:
    validate_limits(args)
    schedule = derive_schedule(args)
    api = validate_api(args.api)
    iorec = resolve_file(args.iorec, "iorec", executable=True)
    node = resolve_file(args.node, "Node", executable=True) if args.workload == "mixed-websocket" else None
    artifact_start = artifact_snapshot(iorec, node)
    project_token_file = resolve_file(args.project_token_file, "project token")
    admin_token_file = resolve_file(args.admin_token_file, "admin token")
    read_private_file(project_token_file, "project token")
    admin_token = read_private_file(admin_token_file, "admin token")
    compose_files = [resolve_file(path, "compose file") for path in args.compose_file]
    compose = compose_base(args.compose_project, compose_files)
    runtime_start = compose_runtime_snapshot(compose, compose_files)
    work_dir, output = prepare_paths(args)
    key_file = work_dir / "iorec.key"
    perf_harness.run_checked([str(iorec), "keygen", "--output", str(key_file)], timeout=30)
    baseline = api_json(api, "/v1/overview", admin_token)
    collector_dirs: list[pathlib.Path] = []
    for index in range(args.collectors):
        path = work_dir / f"c{index:03d}"
        projected_socket = path / "runs" / ("run-" + "0" * 36) / "collector.sock"
        if len(os.fsencode(projected_socket)) > MAX_UNIX_SOCKET_PATH_BYTES:
            raise ValueError(
                "work directory is too long for the recorder's Unix socket; "
                f"choose a shorter --work-dir (projected {projected_socket})"
            )
        (path / "runs").mkdir(mode=0o700, parents=True)
        path.chmod(0o700)
        collector_dirs.append(path)

    fake_process, fake_url = perf_harness.start_fake_server(iorec)
    websocket_server = websocket_fixture.Server() if args.workload == "mixed-websocket" else None
    collectors: list[ManagedProcess] = []
    recorders: list[ManagedProcess] = []
    faults = FaultEvidence()
    started = time.monotonic()
    outage_end = schedule["outage_at_seconds"] + schedule["outage_seconds"]
    outage_started = False
    outage_restored = False
    collectors_restarted = False
    workers_restarted = False
    try:
        for index in range(args.collectors):
            collectors.append(start_collector(
                index,
                iorec,
                api,
                project_token_file,
                key_file,
                collector_dirs[index],
                args.segment_seconds,
                0,
            ))
        wait_until("all collector registrations", 120.0, lambda: len(collector_ids(collector_dirs)) == args.collectors)
        started = time.monotonic()
        for index in range(args.collectors):
            recorders.append(start_recorder(
                index,
                iorec,
                websocket_server.url if websocket_server and index % 2 else fake_url,
                key_file,
                collector_dirs[index],
                args.duration_seconds,
                args.request_interval_seconds,
                websocket=bool(websocket_server and index % 2),
                node=node,
            ))
        wait_until(
            "all active recorder directories",
            60.0,
            lambda: all(only_run_dir(path) for path in collector_dirs),
        )
        running_recorder_hashes = [perf_harness.sha256_file(pathlib.Path(f"/proc/{item.process.pid}/exe")) for item in recorders]
        if any(value != artifact_start[str(iorec)] for value in running_recorder_hashes):
            raise RuntimeError("running recorder does not match the pinned executable")
        print(json.dumps({"stage": "recording", "collectors": args.collectors, "duration_seconds": args.duration_seconds}), flush=True)
        while True:
            elapsed = time.monotonic() - started
            if elapsed >= args.duration_seconds:
                break
            check_live(recorders, "recorder")
            check_live(collectors, "collector")
            if not outage_started and elapsed >= schedule["outage_at_seconds"]:
                faults.outage_pre_events = event_snapshot(iorec, collector_dirs, key_file)
                compose_action(compose, "stop", ["platform-api"])
                faults.platform_outage_started = utc_now()
                wait_until("platform API unavailability", 30.0, lambda: not api_available(api, admin_token))
                faults.platform_unavailable_observed = True
                outage_started = True
                print(json.dumps({"stage": "api_outage_observed"}), flush=True)
            if outage_started and not outage_restored and elapsed >= outage_end:
                faults.outage_post_events = event_snapshot(iorec, collector_dirs, key_file)
                faults.local_recording_advanced = {
                    key: faults.outage_post_events.get(key, 0) > value
                    for key, value in faults.outage_pre_events.items()
                }
                compose_action(compose, "start", ["platform-api"])
                wait_until("platform API restoration", 120.0, lambda: api_available(api, admin_token))
                faults.platform_restored_at = utc_now()
                outage_restored = True
                print(json.dumps({"stage": "api_restored", "all_local_logs_advanced": all(faults.local_recording_advanced.values())}), flush=True)
            if (
                outage_restored
                and not collectors_restarted
                and elapsed >= schedule["collector_restart_at_seconds"]
            ):
                faults.collector_ids_before = collector_ids(collector_dirs)
                stop_processes(collectors)
                collectors = []
                for index in range(args.collectors):
                    collectors.append(start_collector(
                        index,
                        iorec,
                        api,
                        project_token_file,
                        key_file,
                        collector_dirs[index],
                        args.segment_seconds,
                        1,
                    ))
                wait_until("collector re-registration", 120.0, lambda: len(collector_ids(collector_dirs)) == args.collectors)
                faults.collector_ids_after = collector_ids(collector_dirs)
                faults.collector_identity_stable = {
                    key: faults.collector_ids_after.get(key) == value
                    for key, value in faults.collector_ids_before.items()
                }
                faults.collector_restart_at = utc_now()
                collectors_restarted = True
                print(json.dumps({"stage": "collectors_restarted", "identities_stable": all(faults.collector_identity_stable.values())}), flush=True)
            if (
                collectors_restarted
                and not workers_restarted
                and elapsed >= schedule["worker_restart_at_seconds"]
            ):
                compose_action(compose, "restart", ["pipeline-worker"])
                faults.worker_restart_at = utc_now()
                faults.worker_restart_passed = True
                workers_restarted = True
                print(json.dumps({"stage": "workers_restarted"}), flush=True)
            time.sleep(0.2)

        recorder_codes = [close_completed(item) for item in recorders]
        recorders = []
        orchestrator_seconds = time.monotonic() - started
        if any(code != 0 for code in recorder_codes):
            raise RuntimeError(f"recorders failed: {recorder_codes}")
        print(json.dumps({"stage": "drain_and_reconcile"}), flush=True)
        client_results = [
            parse_client_result(path / "recorder.log") for path in collector_dirs
        ]
        run_dirs = [only_run_dir(path) for path in collector_dirs]

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, args.collectors)) as pool:
            local_reports = list(
                pool.map(lambda path: local_validation(iorec, path, key_file), run_dirs)
            )
        spool_reports: list[dict[str, Any]] = []

        def spools_ready() -> bool:
            spool_reports.clear()
            for run_dir, local in zip(run_dirs, local_reports):
                manifest = local["manifest"]
                report = validate_spool_chain(
                    read_spool_chain(run_dir),
                    manifest["run_id"],
                    int(manifest["counts"]["events"]),
                )
                spool_reports.append(report)
            return len(spool_reports) == args.collectors and all(item["passed"] for item in spool_reports)

        wait_until("collector upload drain", args.drain_seconds, spools_ready, interval=2.0)
        expected_segments = sum(item["segments"] for item in spool_reports)
        final_overview: dict[str, Any] = {}

        def platform_drained() -> bool:
            nonlocal final_overview
            passed, final_overview = overview_drained(
                api, admin_token, baseline, args.collectors, expected_segments
            )
            return passed

        wait_until("platform processing drain", args.drain_seconds, platform_drained, interval=2.0)
        recording_ids = [
            recording_id
            for report in spool_reports
            for recording_id in report["recording_ids"]
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            server_reports = list(
                pool.map(lambda recording: verify_server_recording(api, admin_token, recording), recording_ids)
            )
        server_by_id = {item["recording_id"]: item for item in server_reports}
        platform_sequence_checks: list[dict[str, Any]] = []
        for local, spool in zip(local_reports, spool_reports):
            expected = 1
            errors: list[str] = []
            for recording_id in spool["recording_ids"]:
                remote = server_by_id[recording_id]
                if remote["sequence_base"] != expected - 1:
                    errors.append(f"{recording_id} has sequence_base {remote['sequence_base']}, expected {expected - 1}")
                durable = remote["durable_seq"]
                if not isinstance(durable, int) or durable < expected:
                    errors.append(f"{recording_id} has an invalid durable sequence")
                    break
                expected = durable + 1
            final_sequence = int(local["manifest"]["counts"]["events"])
            if expected - 1 != final_sequence:
                errors.append(f"remote chain ends at {expected - 1}, local evidence ends at {final_sequence}")
            platform_sequence_checks.append({"passed": not errors, "errors": errors})

        websocket_projections = []
        for local, client in zip(local_reports, client_results):
            if client.get("workload") == "responses_websocket":
                websocket_projections.append(websocket_soak_validation.verify(
                    lambda path: api_json(api, path, admin_token, timeout=30), local["manifest"]["run_id"], client))
                print(json.dumps({"stage": "websocket_reconciled", "index": len(websocket_projections),
                                  "passed": websocket_projections[-1]["passed"],
                                  "calls": websocket_projections[-1]["calls"]}), flush=True)

        deletion_report = verify_deletion_propagation(
            api,
            admin_token,
            run_dirs[0],
            str(local_reports[0]["manifest"]["run_id"]),
            spool_reports[0]["recording_ids"][-1],
            args.drain_seconds,
        )

        minimum_recorder_seconds = min(
            float(item.get("measurement_seconds", 0.0)) for item in client_results
        )
        runtime_end = compose_runtime_snapshot(compose, compose_files)
        runtime = runtime_provenance(runtime_start, runtime_end)
        all_clients_pass = all(
            item.get("errors") == 0 and item.get("successes", 0) > 0
            for item in client_results
        )
        attempt_counts_match = all(
            int(local["manifest"]["counts"]["transport_attempts"])
            == int(client.get("transport_attempts", client["successes"]))
            for local, client in zip(local_reports, client_results)
        )
        artifact_end = artifact_snapshot(iorec, node)
        websocket_ok = not websocket_server or (len(websocket_projections) == args.collectors // 2 and all(item["passed"] for item in websocket_projections))
        websocket_cross_segment = not websocket_server or all(item["connections_crossing_segments"] > 0 for item in websocket_projections)
        passed = (
            all_clients_pass
            and attempt_counts_match
            and all(item["passed"] for item in local_reports)
            and all(item["passed"] for item in spool_reports)
            and all(item["passed"] for item in server_reports)
            and all(item["passed"] for item in platform_sequence_checks)
            and deletion_report["passed"]
            and faults.platform_unavailable_observed
            and len(faults.local_recording_advanced) == args.collectors
            and all(faults.local_recording_advanced.values())
            and len(faults.collector_identity_stable) == args.collectors
            and all(faults.collector_identity_stable.values())
            and faults.worker_restart_passed
            and runtime["passed"]
            and artifact_start == artifact_end
            and websocket_ok
            and websocket_cross_segment
        )
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "format": "iorec-connected-soak-report-v1",
            "created_at": utc_now(),
            "passed": passed,
            "qualified": False,
            "iorec": {
                "path": str(iorec),
                "sha256": f"sha256:{hashlib.sha256(iorec.read_bytes()).hexdigest()}",
                "version": perf_harness.run_checked([str(iorec), "--version"], timeout=30).stdout.strip(),
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "api": api,
                "compose_project": args.compose_project,
                "compose_files": [str(path) for path in compose_files],
                "baseline_overview": baseline,
                "final_overview": final_overview,
                "runtime_provenance": runtime,
            },
            "configuration": {
                "collectors": args.collectors,
                "workload": args.workload,
                "duration_seconds": args.duration_seconds,
                "request_interval_seconds": args.request_interval_seconds,
                "segment_seconds": args.segment_seconds,
                "drain_seconds": args.drain_seconds,
                **schedule,
            },
            "measurement": {
                "orchestrator_seconds": orchestrator_seconds,
                "minimum_recorder_seconds": minimum_recorder_seconds,
                "client_requests": sum(int(item["requests"]) for item in client_results),
                "client_successes": sum(int(item["successes"]) for item in client_results),
                "client_errors": sum(int(item["errors"]) for item in client_results),
                "local_events": sum(int(item["manifest"]["counts"]["events"]) for item in local_reports),
                "local_attempts": sum(int(item["manifest"]["counts"]["transport_attempts"]) for item in local_reports),
                "recording_segments": expected_segments,
            },
            "faults": vars(faults),
            "checks": {
                "all_clients_pass": all_clients_pass,
                "attempt_counts_match": attempt_counts_match,
                "all_local_integrity_pass": all(item["passed"] for item in local_reports),
                "all_spool_chains_pass": all(item["passed"] for item in spool_reports),
                "all_server_recordings_pass": all(item["passed"] for item in server_reports),
                "all_platform_sequence_chains_pass": all(item["passed"] for item in platform_sequence_checks),
                "platform_drained": all(final_overview.get("checks", {}).values()),
                "deletion_propagation": deletion_report["passed"],
                "platform_runtime_provenance": runtime["passed"],
                "artifacts_unchanged": artifact_start == artifact_end,
                "websocket_projection": websocket_ok,
                "websocket_cross_segment_connections": websocket_cross_segment,
            },
            "client_results": client_results,
            "websocket_projections": websocket_projections,
            "artifact_digests": {"start": artifact_start, "end": artifact_end, "running_recorders": running_recorder_hashes},
            "local_runs": [
                {
                    "run_id": item["manifest"]["run_id"],
                    "events": item["manifest"]["counts"]["events"],
                    "attempts": item["manifest"]["counts"]["transport_attempts"],
                    "passed": item["passed"],
                }
                for item in local_reports
            ],
            "spool_chains": spool_reports,
            "server_recordings": server_reports,
            "platform_sequence_chains": platform_sequence_checks,
            "deletion_propagation": deletion_report,
            "work_dir": str(work_dir),
        }
        report["qualified"] = report_qualifies(report)
        perf_harness.write_report_atomic(output, report)
        print(json.dumps({"output": str(output), "passed": passed, "qualified": report["qualified"]}))
        return report
    except Exception as error:
        # Retain a machine-readable failure even when the run cannot reach the
        # final reconciliation. Never include raw provider bodies or secrets.
        if not output.exists():
            perf_harness.write_report_atomic(output, {
                "schema_version": SCHEMA_VERSION, "format": "iorec-connected-soak-report-v1",
                "created_at": utc_now(), "passed": False, "qualified": False,
                "failure_type": type(error).__name__, "work_dir": str(work_dir),
                "failure_diagnostics": failure_diagnostics(error),
                "faults": vars(faults), "artifact_digests": {"start": artifact_start},
                "configuration": {"collectors": args.collectors, "workload": args.workload,
                                  "duration_seconds": args.duration_seconds},
            })
        raise
    finally:
        if outage_started and not outage_restored:
            try:
                compose_action(compose, "start", ["platform-api"])
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            stop_processes(recorders)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            stop_processes(collectors)
        except (OSError, subprocess.SubprocessError):
            pass
        perf_harness.stop_fake_server(fake_process)
        if websocket_server:
            websocket_server.stop()


def main() -> int:
    args = arguments()
    report = run(args)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as error:
        print(
            f"connected soak failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
