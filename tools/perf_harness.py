#!/usr/bin/env python3
"""Repeatable loopback-only performance and soak harness for iorec.

The harness intentionally uses only the Python standard library. It compares
the same HTTP/SSE client against the built-in fake server directly and through
an encrypted recorder run, then validates every recorded run with iorec.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import http.client
import ipaddress
import json
import math
import os
import pathlib
import platform
import resource
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any


REPORT_SCHEMA_VERSION = 1
DEFAULT_EVENT_STORAGE_LIMIT = 4 * 1024 * 1024 * 1024
DEFAULT_STORAGE_LIMIT = 2 * 1024 * 1024 * 1024
MAX_CONCURRENCY = 1024
MAX_REQUESTS = 10_000_000
MAX_ROUNDS = 100
MAX_DURATION_SECONDS = 7 * 24 * 60 * 60
MAX_RATE = 100_000
MAX_PAYLOAD_BYTES = 120 * 1024 * 1024
MAX_RESPONSE_CHUNKS = 100_000
MAX_RESPONSE_CHUNK_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 128 * 1024 * 1024
MAX_DELAY_MS = 60_000
MAX_BLOB_FILES_PER_RUN = 250_000


@dataclass(frozen=True)
class ProcessMeasurement:
    wall_seconds: float
    user_cpu_seconds: float
    system_cpu_seconds: float

    @property
    def cpu_seconds(self) -> float:
        return self.user_cpu_seconds + self.system_cpu_seconds


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure iorec overhead or run a validated soak workload"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    benchmark = subparsers.add_parser("benchmark")
    add_common_orchestrator_arguments(benchmark)
    benchmark.add_argument("--requests", type=positive_int, default=200)
    benchmark.add_argument("--warmup", type=nonnegative_int, default=20)
    benchmark.add_argument("--rounds", type=positive_int, default=3)

    soak = subparsers.add_parser("soak")
    add_common_orchestrator_arguments(soak)
    soak.add_argument("--duration-seconds", type=positive_float, required=True)
    soak.add_argument(
        "--rate",
        type=positive_float,
        default=1.0,
        help="approximate total requests per second across all workers",
    )

    client = subparsers.add_parser("_client", help=argparse.SUPPRESS)
    client.add_argument("--url")
    client.add_argument("--url-env")
    client.add_argument("--requests", type=nonnegative_int)
    client.add_argument("--duration-seconds", type=positive_float)
    client.add_argument("--rate", type=positive_float)
    client.add_argument("--warmup", type=nonnegative_int, default=0)
    client.add_argument("--concurrency", type=positive_int, required=True)
    client.add_argument("--payload-bytes", type=nonnegative_int, required=True)
    client.add_argument("--response-chunks", type=positive_int, required=True)
    client.add_argument("--response-chunk-bytes", type=nonnegative_int, required=True)
    client.add_argument("--delay-ms", type=nonnegative_int, required=True)
    return parser.parse_args()


def add_common_orchestrator_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--iorec",
        type=pathlib.Path,
        default=pathlib.Path("target/release/iorec"),
    )
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--work-dir", type=pathlib.Path)
    parser.add_argument("--concurrency", type=positive_int, default=4)
    parser.add_argument("--payload-bytes", type=nonnegative_int, default=1024)
    parser.add_argument("--response-chunks", type=positive_int, default=3)
    parser.add_argument("--response-chunk-bytes", type=nonnegative_int, default=256)
    parser.add_argument("--delay-ms", type=nonnegative_int, default=5)
    parser.add_argument(
        "--max-event-storage-bytes",
        type=positive_int,
        default=DEFAULT_EVENT_STORAGE_LIMIT,
    )
    parser.add_argument(
        "--max-run-blob-storage-bytes",
        type=positive_int,
        default=DEFAULT_STORAGE_LIMIT,
    )


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def require_loopback_http(raw_url: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.port is None:
        raise ValueError("benchmark URL must be an explicit http://host:port URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise ValueError("benchmark URL host must be a literal loopback address") from error
    if not address.is_loopback:
        raise ValueError("benchmark refuses all non-loopback destinations")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("benchmark URL must not contain credentials, query, or fragment")
    return parsed


def validate_workload_limits(arguments: argparse.Namespace) -> None:
    if arguments.concurrency > MAX_CONCURRENCY:
        raise ValueError(f"concurrency exceeds {MAX_CONCURRENCY}")
    if arguments.payload_bytes > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload bytes exceed {MAX_PAYLOAD_BYTES}")
    if arguments.response_chunks > MAX_RESPONSE_CHUNKS:
        raise ValueError(f"response chunks exceed {MAX_RESPONSE_CHUNKS}")
    if arguments.response_chunk_bytes > MAX_RESPONSE_CHUNK_BYTES:
        raise ValueError(f"response chunk bytes exceed {MAX_RESPONSE_CHUNK_BYTES}")
    if arguments.response_chunks * arguments.response_chunk_bytes > MAX_RESPONSE_BYTES:
        raise ValueError(f"response payload exceeds {MAX_RESPONSE_BYTES} bytes")
    if arguments.delay_ms > MAX_DELAY_MS:
        raise ValueError(f"delay exceeds {MAX_DELAY_MS} ms")
    if arguments.command == "benchmark":
        if arguments.requests > MAX_REQUESTS or arguments.warmup > MAX_REQUESTS:
            raise ValueError(f"request count exceeds {MAX_REQUESTS}")
        if arguments.rounds > MAX_ROUNDS:
            raise ValueError(f"round count exceeds {MAX_ROUNDS}")
        validate_recorded_run_scale(
            arguments.requests + arguments.warmup,
            arguments.response_chunks,
        )
    elif arguments.command == "soak":
        if arguments.duration_seconds > MAX_DURATION_SECONDS:
            raise ValueError(f"duration exceeds {MAX_DURATION_SECONDS} seconds")
        if arguments.rate > MAX_RATE:
            raise ValueError(f"rate exceeds {MAX_RATE} requests per second")
        estimated_requests = (
            math.ceil(arguments.duration_seconds * arguments.rate)
            + arguments.concurrency
        )
        validate_recorded_run_scale(estimated_requests, arguments.response_chunks)
    elif arguments.command == "_client":
        if arguments.requests is not None and arguments.requests > MAX_REQUESTS:
            raise ValueError(f"request count exceeds {MAX_REQUESTS}")
        if (
            arguments.duration_seconds is not None
            and arguments.duration_seconds > MAX_DURATION_SECONDS
        ):
            raise ValueError(f"duration exceeds {MAX_DURATION_SECONDS} seconds")
        if arguments.rate is not None and arguments.rate > MAX_RATE:
            raise ValueError(f"rate exceeds {MAX_RATE} requests per second")


def validate_recorded_run_scale(requests: int, response_chunks: int) -> None:
    if requests > MAX_REQUESTS:
        raise ValueError(
            f"estimated recorded requests exceed the safety limit of {MAX_REQUESTS}"
        )
    estimated_blob_files = requests * (1 + response_chunks)
    if estimated_blob_files > MAX_BLOB_FILES_PER_RUN:
        raise ValueError(
            "estimated unique request/response blobs exceed the recorder's "
            f"{MAX_BLOB_FILES_PER_RUN}-file run limit"
        )


def client_main(arguments: argparse.Namespace) -> int:
    raw_url = arguments.url
    if arguments.url_env:
        raw_url = os.environ.get(arguments.url_env)
    if not raw_url:
        raise ValueError("client URL is absent")
    parsed = require_loopback_http(raw_url)
    if (arguments.requests is None) == (arguments.duration_seconds is None):
        raise ValueError("client requires exactly one of --requests or --duration-seconds")
    if arguments.rate is not None and arguments.duration_seconds is None:
        raise ValueError("--rate is valid only with --duration-seconds")

    if arguments.warmup:
        warmup = execute_workload(
            parsed,
            requests=arguments.warmup,
            duration_seconds=None,
            rate=None,
            concurrency=arguments.concurrency,
            payload_bytes=arguments.payload_bytes,
            response_chunks=arguments.response_chunks,
            response_chunk_bytes=arguments.response_chunk_bytes,
            delay_ms=arguments.delay_ms,
        )
        if warmup["errors"]:
            raise RuntimeError(f"warmup failed: {warmup['error_samples']}")

    measured = execute_workload(
        parsed,
        requests=arguments.requests,
        duration_seconds=arguments.duration_seconds,
        rate=arguments.rate,
        concurrency=arguments.concurrency,
        payload_bytes=arguments.payload_bytes,
        response_chunks=arguments.response_chunks,
        response_chunk_bytes=arguments.response_chunk_bytes,
        delay_ms=arguments.delay_ms,
    )
    measured["warmup_requests"] = arguments.warmup
    print(json.dumps(measured, separators=(",", ":"), sort_keys=True), flush=True)
    return 0


def execute_workload(
    parsed_url: urllib.parse.SplitResult,
    *,
    requests: int | None,
    duration_seconds: float | None,
    rate: float | None,
    concurrency: int,
    payload_bytes: int,
    response_chunks: int,
    response_chunk_bytes: int,
    delay_ms: int,
) -> dict[str, Any]:
    path_prefix = parsed_url.path.rstrip("/")
    request_path = f"{path_prefix}/v1/responses"
    deadline = None if duration_seconds is None else time.monotonic() + duration_seconds
    work_counts = distribute_work(requests, concurrency)
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                client_worker,
                worker,
                count,
                deadline,
                rate,
                concurrency,
                parsed_url.hostname,
                parsed_url.port,
                request_path,
                payload_bytes,
                response_chunks,
                response_chunk_bytes,
                delay_ms,
            )
            for worker, count in enumerate(work_counts)
        ]
        results = [future.result() for future in futures]
    wall_seconds = time.monotonic() - start
    latencies = [latency for result in results for latency in result["latencies_ms"]]
    errors = [error for result in results for error in result["errors"]]
    response_bytes = sum(result["response_bytes"] for result in results)
    successes = len(latencies)
    return {
        "requests": successes + len(errors),
        "successes": successes,
        "errors": len(errors),
        "error_samples": errors[:10],
        "response_bytes": response_bytes,
        "measurement_seconds": wall_seconds,
        "requests_per_second": safe_ratio(successes, wall_seconds),
        "mib_per_second": safe_ratio(response_bytes, wall_seconds) / (1024 * 1024),
        "ttft_ms": latency_summary(latencies),
        "_ttft_samples_ms": latencies,
    }


def distribute_work(requests: int | None, concurrency: int) -> list[int | None]:
    if requests is None:
        return [None] * concurrency
    quotient, remainder = divmod(requests, concurrency)
    return [quotient + int(worker < remainder) for worker in range(concurrency)]


def client_worker(
    worker: int,
    request_count: int | None,
    deadline: float | None,
    rate: float | None,
    concurrency: int,
    host: str,
    port: int,
    path: str,
    payload_bytes: int,
    response_chunks: int,
    response_chunk_bytes: int,
    delay_ms: int,
) -> dict[str, Any]:
    connection: http.client.HTTPConnection | None = None
    latencies: list[float] = []
    errors: list[str] = []
    response_bytes = 0
    iteration = 0
    interval = None if rate is None else concurrency / rate
    worker_start = time.monotonic()
    while request_count is None or iteration < request_count:
        if deadline is not None and time.monotonic() >= deadline:
            break
        if interval is not None:
            target = worker_start + iteration * interval
            remaining = target - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            if deadline is not None and time.monotonic() >= deadline:
                break
        payload = json.dumps(
            {
                "model": "iorec-perf-model",
                "input": "x" * payload_bytes,
                "metadata": {"worker": worker, "iteration": iteration},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        started = time.perf_counter_ns()
        try:
            if connection is None:
                connection = http.client.HTTPConnection(host, port, timeout=30)
            connection.request(
                "POST",
                path,
                body=payload,
                headers={
                    "content-type": "application/json",
                    "x-request-id": f"perf-{worker}-{iteration}",
                    "x-iorec-chunks": str(response_chunks),
                    "x-iorec-chunk-bytes": str(response_chunk_bytes),
                    "x-iorec-delay-ms": str(delay_ms),
                },
            )
            response = connection.getresponse()
            first = response.read(1)
            first_byte_ns = time.perf_counter_ns()
            remainder = response.read()
            if response.status != 200 or not first:
                raise RuntimeError(
                    f"unexpected response status/body: {response.status}/{len(first)}"
                )
            response_bytes += len(first) + len(remainder)
            latencies.append((first_byte_ns - started) / 1_000_000)
        except Exception as error:  # Workload failures are report data.
            errors.append(f"{type(error).__name__}: {error}"[:512])
            if connection is not None:
                connection.close()
            connection = None
        iteration += 1
    if connection is not None:
        connection.close()
    return {
        "latencies_ms": latencies,
        "errors": errors,
        "response_bytes": response_bytes,
    }


def latency_summary(samples: list[float]) -> dict[str, float | int | None]:
    if not samples:
        return {"samples": 0, "min": None, "p50": None, "p95": None, "p99": None, "max": None}
    ordered = sorted(samples)
    return {
        "samples": len(samples),
        "min": ordered[0],
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "p99": percentile(ordered, 99),
        "max": ordered[-1],
    }


def percentile(ordered: list[float], percentile_value: float) -> float:
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile_value / 100
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    fraction = rank - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def orchestrator_main(arguments: argparse.Namespace) -> int:
    iorec = arguments.iorec.expanduser().resolve(strict=True)
    if not iorec.is_file() or not os.access(iorec, os.X_OK):
        raise ValueError(f"iorec binary is not executable: {iorec}")
    output = absolute_output(arguments.output)
    work_dir = prepare_work_directory(arguments.work_dir)
    key_file = work_dir / "iorec.key"
    run_checked([str(iorec), "keygen", "--output", str(key_file)], timeout=30)
    fake = start_fake_server(iorec)
    try:
        if arguments.command == "benchmark":
            report = run_benchmark(arguments, iorec, work_dir, key_file, fake[1])
        else:
            report = run_soak(arguments, iorec, work_dir, key_file, fake[1])
    finally:
        stop_fake_server(fake[0])
    write_report_atomic(output, report)
    print(json.dumps({"output": str(output), "work_dir": str(work_dir), "passed": report["passed"]}))
    return 0 if report["passed"] else 2


def prepare_work_directory(requested: pathlib.Path | None) -> pathlib.Path:
    if requested is None:
        path = pathlib.Path(tempfile.mkdtemp(prefix="iorec-perf-"))
    else:
        path = requested.expanduser().resolve()
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)
    return path


def absolute_output(requested: pathlib.Path) -> pathlib.Path:
    parent = requested.expanduser().parent.resolve(strict=True)
    output = parent / requested.name
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite report: {output}")
    return output


def start_fake_server(iorec: pathlib.Path) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [str(iorec), "fake-server", "--listen", "127.0.0.1:0"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    events = selector.select(timeout=10)
    selector.close()
    if not events:
        process.kill()
        raise TimeoutError("fake server did not publish its address")
    raw_url = process.stdout.readline().strip()
    require_loopback_http(raw_url)
    return process, raw_url


def stop_fake_server(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=10)


def client_command(arguments: argparse.Namespace, url: str | None, *, soak: bool) -> list[str]:
    command = [sys.executable, str(pathlib.Path(__file__).resolve()), "_client"]
    if url is None:
        command.extend(["--url-env", "IOREC_PROXY_URL"])
    else:
        command.extend(["--url", url])
    if soak:
        command.extend(
            [
                "--duration-seconds",
                str(arguments.duration_seconds),
                "--rate",
                str(arguments.rate),
            ]
        )
    else:
        command.extend(
            [
                "--requests",
                str(arguments.requests),
                "--warmup",
                str(arguments.warmup),
            ]
        )
    command.extend(
        [
            "--concurrency",
            str(arguments.concurrency),
            "--payload-bytes",
            str(arguments.payload_bytes),
            "--response-chunks",
            str(arguments.response_chunks),
            "--response-chunk-bytes",
            str(arguments.response_chunk_bytes),
            "--delay-ms",
            str(arguments.delay_ms),
        ]
    )
    return command


def run_benchmark(
    arguments: argparse.Namespace,
    iorec: pathlib.Path,
    work_dir: pathlib.Path,
    key_file: pathlib.Path,
    fake_url: str,
) -> dict[str, Any]:
    direct_results: list[dict[str, Any]] = []
    direct_process: list[ProcessMeasurement] = []
    recorded_results: list[dict[str, Any]] = []
    recorded_process: list[ProcessMeasurement] = []
    validations: list[dict[str, Any]] = []
    runs_dir = work_dir / "runs"
    runs_dir.mkdir(mode=0o700)
    timeout = max(120.0, arguments.requests * (arguments.delay_ms / 1000 + 1) + 60)

    for round_index in range(arguments.rounds):
        operations = ["direct", "recorded"]
        if round_index % 2:
            operations.reverse()
        for operation in operations:
            if operation == "direct":
                result, measurement = measured_command(
                    client_command(arguments, fake_url, soak=False), timeout=timeout
                )
                direct_results.append(result)
                direct_process.append(measurement)
            else:
                before = set(run_directories(runs_dir))
                command = recorder_command(
                    arguments,
                    iorec,
                    runs_dir,
                    key_file,
                    fake_url,
                    client_command(arguments, None, soak=False),
                )
                result, measurement = measured_command(command, timeout=timeout)
                after = set(run_directories(runs_dir))
                created = sorted(after - before)
                if len(created) != 1:
                    raise RuntimeError(f"expected one recorder run, found {created}")
                validation = validate_run(iorec, created[0], key_file)
                expected = arguments.requests + arguments.warmup
                validation["expected_attempts"] = expected
                validation["attempt_count_matches"] = (
                    validation["manifest"]["counts"]["transport_attempts"] == expected
                )
                validation["event_storage_within_budget"] = (
                    validation["manifest"]["counts"]["event_storage_bytes"]
                    <= arguments.max_event_storage_bytes
                )
                validation["blob_storage_within_budget"] = (
                    validation["manifest"]["counts"]["blob_storage_bytes"]
                    <= arguments.max_run_blob_storage_bytes
                )
                direct_success = result["errors"] == 0 and result["successes"] == arguments.requests
                validation["client_workload_passed"] = direct_success
                validations.append(validation)
                recorded_results.append(result)
                recorded_process.append(measurement)

    direct = aggregate_measurements(direct_results, direct_process)
    recorded = aggregate_measurements(recorded_results, recorded_process)
    passed = (
        direct["errors"] == 0
        and recorded["errors"] == 0
        and all(validation_passed(validation) for validation in validations)
    )
    return report_base("iorec-performance-report-v1", arguments, iorec, work_dir) | {
        "passed": passed,
        "methodology": {
            "baseline": "same stdlib HTTP/SSE client directly to built-in fake server",
            "recorded": "same client through one encrypted full-body iorec run per round",
            "ttft": "client monotonic time from request start through first response body byte",
            "cpu": "waited child user+system CPU; fake-server CPU excluded from both paths",
            "round_order": "alternating direct-first and recorded-first",
            "startup_in_cpu_and_outer_wall": True,
        },
        "direct": direct,
        "recorded": recorded,
        "overhead": {
            "ttft_p50_percent": percent_change(recorded["ttft_ms"]["p50"], direct["ttft_ms"]["p50"]),
            "ttft_p95_percent": percent_change(recorded["ttft_ms"]["p95"], direct["ttft_ms"]["p95"]),
            "throughput_percent": percent_change(recorded["requests_per_second"], direct["requests_per_second"]),
            "cpu_per_request_percent": percent_change(recorded["cpu_ms_per_request"], direct["cpu_ms_per_request"]),
        },
        "run_validations": validations,
    }


def run_soak(
    arguments: argparse.Namespace,
    iorec: pathlib.Path,
    work_dir: pathlib.Path,
    key_file: pathlib.Path,
    fake_url: str,
) -> dict[str, Any]:
    runs_dir = work_dir / "runs"
    runs_dir.mkdir(mode=0o700)
    command = recorder_command(
        arguments,
        iorec,
        runs_dir,
        key_file,
        fake_url,
        client_command(arguments, None, soak=True),
    )
    result, measurement = measured_command(
        command, timeout=arguments.duration_seconds + 180
    )
    runs = run_directories(runs_dir)
    if len(runs) != 1:
        raise RuntimeError(f"expected one recorder run, found {runs}")
    validation = validate_run(iorec, runs[0], key_file)
    validation["expected_attempts"] = result["successes"]
    validation["attempt_count_matches"] = (
        validation["manifest"]["counts"]["transport_attempts"] == result["successes"]
    )
    validation["event_storage_within_budget"] = (
        validation["manifest"]["counts"]["event_storage_bytes"]
        <= arguments.max_event_storage_bytes
    )
    validation["blob_storage_within_budget"] = (
        validation["manifest"]["counts"]["blob_storage_bytes"]
        <= arguments.max_run_blob_storage_bytes
    )
    validation["client_workload_passed"] = result["errors"] == 0
    measured = aggregate_measurements([result], [measurement])
    passed = result["successes"] > 0 and validation_passed(validation)
    return report_base("iorec-soak-report-v1", arguments, iorec, work_dir) | {
        "passed": passed,
        "methodology": {
            "recorded": "rate-limited concurrent client through one encrypted full-body recorder run",
            "ttft": "client monotonic time from request start through first response body byte",
            "cpu": "waited recorder process tree user+system CPU; fake-server CPU excluded",
        },
        "recorded": measured,
        "run_validation": validation,
    }


def recorder_command(
    arguments: argparse.Namespace,
    iorec: pathlib.Path,
    runs_dir: pathlib.Path,
    key_file: pathlib.Path,
    fake_url: str,
    target: list[str],
) -> list[str]:
    return [
        str(iorec),
        "run",
        "--runs-dir",
        str(runs_dir),
        "--upstream",
        fake_url,
        "--provider",
        "none",
        "--adapter",
        "none",
        "--key-file",
        str(key_file),
        "--max-event-storage-bytes",
        str(arguments.max_event_storage_bytes),
        "--max-run-blob-storage-bytes",
        str(arguments.max_run_blob_storage_bytes),
        "--",
        *target,
    ]


def measured_command(command: list[str], *, timeout: float) -> tuple[dict[str, Any], ProcessMeasurement]:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_measured_process(process)
        raise
    except BaseException:
        stop_measured_process(process)
        raise
    wall = time.monotonic() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if process.returncode != 0:
        raise RuntimeError(
            f"command failed with {process.returncode}: "
            f"stdout={stdout[-2000:]!r} stderr={stderr[-4000:]!r}"
        )
    result = parse_last_json_line(stdout)
    return result, ProcessMeasurement(
        wall_seconds=wall,
        user_cpu_seconds=after.ru_utime - before.ru_utime,
        system_cpu_seconds=after.ru_stime - before.ru_stime,
    )


def stop_measured_process(process: subprocess.Popen[str]) -> None:
    """Stop the recorder first so it can forward SIGTERM and finalize evidence."""
    if process.poll() is not None:
        process.communicate()
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.communicate(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass

    # The recorder starts in its own session and may place the target in another
    # process group. A group-only kill would therefore orphan that target.
    session_pids: list[int] = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            if os.getsid(pid) == process.pid:
                session_pids.append(pid)
        except (ProcessLookupError, PermissionError):
            continue
    session_pids.sort(key=lambda pid: pid == process.pid)
    for pid in session_pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.communicate(timeout=10)


def run_checked(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )


def parse_last_json_line(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError(f"command did not emit a JSON object: {output[-2000:]!r}")


def run_directories(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path.resolve()
        for path in root.iterdir()
        if path.is_dir() and not path.is_symlink() and path.name.startswith("run-")
    )


def validate_run(
    iorec: pathlib.Path, run_dir: pathlib.Path, key_file: pathlib.Path
) -> dict[str, Any]:
    inspection = run_checked(
        [
            str(iorec),
            "inspect",
            str(run_dir),
            "--json",
            "--verify-blobs",
            "--key-file",
            str(key_file),
        ],
        timeout=120,
    )
    verification = run_checked(
        [
            str(iorec),
            "verify",
            str(run_dir),
            "--profile",
            "integrity",
            "--json",
            "--key-file",
            str(key_file),
        ],
        timeout=120,
    )
    return {
        "run_dir": str(run_dir),
        "manifest": json.loads(inspection.stdout)["manifest"],
        "missing_blobs": len(json.loads(inspection.stdout)["missing_blobs"]),
        "corrupt_blobs": len(json.loads(inspection.stdout)["corrupt_blobs"]),
        "discarded_tail_bytes": json.loads(inspection.stdout)["log"]["discarded_tail_bytes"],
        "integrity_verifier": json.loads(verification.stdout),
    }


def validation_passed(validation: dict[str, Any]) -> bool:
    manifest = validation["manifest"]
    return (
        validation.get("client_workload_passed", False)
        and validation.get("attempt_count_matches", False)
        and validation.get("event_storage_within_budget", False)
        and validation.get("blob_storage_within_budget", False)
        and validation["missing_blobs"] == 0
        and validation["corrupt_blobs"] == 0
        and validation["discarded_tail_bytes"] == 0
        and validation["integrity_verifier"]["passed"]
        and manifest["coverage"]["capture_drops"] == 0
        and manifest["counts"]["incomplete_attempts"] == 0
    )


def aggregate_measurements(
    results: list[dict[str, Any]], measurements: list[ProcessMeasurement]
) -> dict[str, Any]:
    samples = [sample for result in results for sample in result.pop("_ttft_samples_ms")]
    successes = sum(result["successes"] for result in results)
    errors = sum(result["errors"] for result in results)
    response_bytes = sum(result["response_bytes"] for result in results)
    measurement_seconds = sum(result["measurement_seconds"] for result in results)
    cpu_seconds = sum(measurement.cpu_seconds for measurement in measurements)
    return {
        "rounds": len(results),
        "requests": successes + errors,
        "successes": successes,
        "errors": errors,
        "error_samples": [
            error for result in results for error in result["error_samples"]
        ][:10],
        "response_bytes": response_bytes,
        "measurement_seconds": measurement_seconds,
        "outer_wall_seconds": sum(measurement.wall_seconds for measurement in measurements),
        "user_cpu_seconds": sum(measurement.user_cpu_seconds for measurement in measurements),
        "system_cpu_seconds": sum(measurement.system_cpu_seconds for measurement in measurements),
        "cpu_seconds": cpu_seconds,
        "cpu_ms_per_request": 1000 * safe_ratio(cpu_seconds, successes),
        "requests_per_second": safe_ratio(successes, measurement_seconds),
        "mib_per_second": safe_ratio(response_bytes, measurement_seconds) / (1024 * 1024),
        "ttft_ms": latency_summary(samples),
    }


def report_base(
    report_format: str,
    arguments: argparse.Namespace,
    iorec: pathlib.Path,
    work_dir: pathlib.Path,
) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "format": report_format,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passed": False,
        "iorec": {
            "path": str(iorec),
            "sha256": sha256_file(iorec),
            "version": run_checked([str(iorec), "--version"], timeout=30).stdout.strip(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "work_dir": str(work_dir),
        "configuration": {
            key: value
            for key, value in vars(arguments).items()
            if key not in {"output", "work_dir", "iorec", "command"}
        },
    }


def sha256_file(path: pathlib.Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def write_report_atomic(output: pathlib.Path, report: dict[str, Any]) -> None:
    temporary = output.parent / f".iorec-report-{os.getpid()}-{time.time_ns()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(report, target, indent=2, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, output)
        temporary.unlink()
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def safe_ratio(numerator: float | int, denominator: float | int) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def percent_change(value: float | None, baseline: float | None) -> float | None:
    if value is None or baseline in {None, 0}:
        return None
    return (value / baseline - 1) * 100


def main() -> int:
    arguments = parse_arguments()
    validate_workload_limits(arguments)
    if arguments.command == "_client":
        return client_main(arguments)
    return orchestrator_main(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as error:
        print(f"perf harness failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
