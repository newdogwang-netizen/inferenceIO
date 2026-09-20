#!/usr/bin/env python3
"""Controlled local Harbor audit: record, verify, import, qualify, clean up.

This audit profile is not a leaderboard-compatible sandbox. Raw Harbor logs
remain private in the work directory. Only report.json is a publication
candidate; review task/model identifiers before publishing it. No credentials,
payloads, TLS secrets or raw transport reports are copied into that report.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

from harbor_input_provenance import InputFailure, audit_definitions, fresh_identity, harbor_environment, image_compose, file_identity, measurement_definitions
from m3_experiment_plan import PlanFailure, bind_case
from m3_trial_ledger import Ledger, LedgerFailure
from harbor_task_network import NetworkFailure, network_compose, probe_network

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/@+~-]{0,255}\Z")
MAX_JSON = 64 << 20


class Failure(Exception):
    """Fixed diagnostic codes only; exception payloads may contain secrets."""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path: Path):
    with path.open("rb") as src:
        raw = src.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise Failure("json_limit_exceeded")
    return json.loads(raw)


def atomic_json(path: Path, value):
    temporary = path.with_name(path.name + ".next")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def private_path(path: Path, directory=False):
    info = path.lstat()
    if (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) is False:
        raise Failure("private_path_wrong_type")
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Failure("private_path_requires_owner_only_permissions")


def local_url(value: str) -> str:
    u = urlsplit(value)
    host = u.hostname
    if host == "localhost":
        host = "127.0.0.1"
    try:
        valid = ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        valid = False
    if not valid or u.scheme != "http" or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise Failure("only_explicit_loopback_http_origins_allowed")
    # Never use environment proxies, resolve arbitrary DNS, or follow redirects.
    return f"http://{'['+host+']' if ':' in host else host}:{u.port or 80}"


def api_request(origin, path, token="", method="GET", value=None, bundle: Path | None = None):
    u = urlsplit(local_url(origin))
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if value is not None:
        data = json.dumps(value, allow_nan=False).encode()
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(u.hostname, u.port, timeout=120 if bundle else 15)
    try:
        with contextlib.ExitStack() as stack:
            if bundle:
                data = stack.enter_context(bundle.open("rb"))
                headers.update({"Content-Length": str(bundle.stat().st_size), "Content-Type": "application/x-tar"})
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_JSON + 1)
            if not 200 <= response.status < 300:
                raise Failure(f"platform_http_{response.status}")
            if len(raw) > MAX_JSON:
                raise Failure("platform_response_limit_exceeded")
            return json.loads(raw) if raw else None
    finally:
        connection.close()


class Workspace:
    def __init__(self, path: Path):
        self.path = path.absolute()
        self.lock = None

    def __enter__(self):
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_path(self.path, directory=True)
        # Refuse to claim an existing unrelated directory as our cleanup scope.
        if not (self.path / "state.json").exists() and any(p.name not in (".lock", "state.json.next") for p in self.path.iterdir()):
            raise Failure("work_directory_not_empty_or_initialized")
        fd = os.open(self.path / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "r+")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise Failure("workflow_or_child_still_running_no_restart") from None
        return self

    def cleanup(self):
        scratch = self.path / "scratch"
        if scratch.exists() or scratch.is_symlink():
            private_path(scratch, directory=True)
            # Only this tool's dedicated plaintext staging directory is removed.
            shutil.rmtree(scratch)

    def __exit__(self, *_):
        try:
            self.cleanup()
        finally:
            self.lock.close()


def benchmark_from_trial(trial: Path):
    result = read_json(trial / "result.json")
    if not result.get("finished_at"):
        raise Failure("trial_not_finished_no_restart")
    error = (result.get("exception_info") or {}).get("exception_type", "")
    status = "timeout" if "timeout" in error.lower() else "error" if error else "completed"
    reward = (result.get("verifier_result") or {}).get("rewards", {}).get("reward")
    if reward is not None and (isinstance(reward, bool) or not isinstance(reward, (int, float)) or not math.isfinite(reward)):
        raise Failure("invalid_verifier_reward")
    if status != "completed":
        reward = None
    info = result.get("agent_info") or {}
    model = info.get("model_info") or {}
    b = {"framework": "harbor", "task": result.get("task_name"), "trial": trial.name,
         "agent": info.get("name"), "model": f"{model.get('provider','')}/{model.get('name','')}",
         "status": status, "reward": reward, "artifact_sha256": digest(trial / "result.json")}
    if any(not isinstance(b[key], str) or not IDENTIFIER.fullmatch(b[key]) for key in ("task", "trial", "agent", "model")):
        raise Failure("unusable_benchmark_identifiers")
    cost = (result.get("agent_result") or {}).get("cost_usd")
    if cost is not None and (isinstance(cost, bool) or not isinstance(cost, (int, float)) or not math.isfinite(cost) or cost < 0):
        raise Failure("invalid_reported_cost")
    return b, {"agent_version": info.get("version"), "reported_cost_usd": cost}


def dominant_measurement(measurements):
    """Select one clearly dominant CLI invocation without hiding auxiliaries."""
    if not measurements:
        raise Failure("fresh_trial_measurement_missing_or_invalid")
    ordered = sorted(measurements, key=lambda value: (-value["wall_seconds"], value["invocation_id"]))
    primary = ordered[0]
    auxiliaries = ordered[1:]
    if auxiliaries and (primary["wall_seconds"] <= 0 or primary["wall_seconds"] < 4 * auxiliaries[0]["wall_seconds"]):
        raise Failure("multiple_agent_invocations_without_unique_dominant_capture")
    return primary, auxiliaries


def parse_utc_timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise Failure("invalid_capture_time")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Failure("invalid_capture_time") from None
    if parsed.utcoffset() != dt.timedelta(0):
        raise Failure("invalid_capture_time")
    return parsed


def pair_measurements_and_captures(trial: Path, measurements):
    manifests = list((trial / "agent/iorec-runs").glob("run-*/manifest.json"))
    if not 1 <= len(manifests) <= 16 or len(manifests) != len(measurements):
        raise Failure("measurement_capture_count_mismatch")
    captures = []
    for path in manifests:
        run = path.parent
        if run.is_symlink() or path.is_symlink() or not path.is_file():
            raise Failure("invalid_capture_manifest_path")
        manifest = read_json(path)
        if manifest.get("status") != "finished" or not manifest.get("storage", {}).get("encryption"):
            raise Failure("capture_not_finished_and_encrypted")
        if not IDENTIFIER.fullmatch(manifest.get("run_id", "")) or run.name != manifest["run_id"]:
            raise Failure("invalid_capture_identifier")
        exit_code = manifest.get("exit_code")
        if type(exit_code) is not int or not -64 <= exit_code <= 255:
            raise Failure("invalid_capture_exit")
        captures.append({"path": run, "manifest": manifest,
                         "started_at": parse_utc_timestamp(manifest.get("started_at")),
                         "exit_code": exit_code})
    available = captures[:]
    pairs = []
    for measurement in measurements:
        started = parse_utc_timestamp(measurement.get("started_at"))
        compatible = sorted(
            ((abs((capture["started_at"] - started).total_seconds()), capture)
             for capture in available if capture["exit_code"] == measurement.get("exit_code")),
            key=lambda item: (item[0], item[1]["manifest"]["run_id"]),
        )
        if not compatible or compatible[0][0] > 2:
            raise Failure("measurement_capture_time_or_exit_mismatch")
        if len(compatible) > 1 and compatible[1][0] == compatible[0][0]:
            raise Failure("measurement_capture_pairing_ambiguous")
        capture = compatible[0][1]
        available.remove(capture)
        pairs.append({**capture, "measurement": measurement})
    if available:
        raise Failure("measurement_capture_pairing_incomplete")
    return pairs


def harbor_config(args, work):
    agent = getattr(args, "agent", "codex")
    kwargs = {"reasoning_effort": "high", "web_search": "disabled"} if agent == "codex" else ({"max_turns": 60} if agent == "claude" else {})
    if agent == "claude" and getattr(args, "agent_budget_usd", None) is not None:
        kwargs["max_budget_usd"] = str(args.agent_budget_usd)
    overlays = [str(ROOT / "examples/harbor-audit-compose.yaml")]
    if getattr(args, "task_image", None):
        overlays.append(str(work / "task-image.compose.json"))
    if getattr(args, "task_network_subnet", None):
        overlays.append(str(work / "task-network.compose.json"))
    return {"job_name": "audit", "jobs_dir": str(work / "jobs"), "n_attempts": 1,
            "n_concurrent_trials": 1, "retry": {"max_retries": 0},
            "tasks": [{"path": str(args.task)}],
            "environment": {"type": "docker", "delete": True, "extra_docker_compose": overlays},
            "agents": [{"import_path": audit_definitions().AGENTS[agent]["profile"], "model_name": args.model,
                        "override_timeout_sec": args.agent_timeout, "max_timeout_sec": args.agent_timeout,
                        "override_setup_timeout_sec": 600,
                        "kwargs": kwargs}],
            "verifier": {"override_timeout_sec": getattr(args, "verifier_timeout", 300),
                         "max_timeout_sec": getattr(args, "verifier_timeout", 300)}}


class Workflow:
    def __init__(self, args, work: Workspace):
        self.a, self.work = args, work
        self.state_path = work.path / "state.json"
        self.state = read_json(self.state_path) if self.state_path.exists() else {"schema_version": 1, "stages": {}}
        self.phase = "preflight"
        self.token = ""
        self.ledger = None
        self.experiment_control = None
        if args.token_file:
            private_path(args.token_file)
            self.token = args.token_file.read_text().strip()
            if not self.token or len(self.token) > 8192 or any(c.isspace() for c in self.token):
                raise Failure("invalid_private_platform_token")

    def save(self):
        atomic_json(self.state_path, self.state)

    def publish_report(self):
        atomic_json(self.work.path / "report.json", {
            "schema_version": 1, "generated_at": now(), "workflow_status": self.state.get("status"),
            "qualification_passed": self.state.get("status") == "completed",
            "recording_mode": getattr(self.a, "recording_mode", "on"),
            "baseline_completed": self.state.get("status") == "baseline_completed",
            "trial_summary": self.state.get("trial_summary"),
            "benchmark_score_is_separate": True,
            "plaintext_staging_cleaned": self.state.get("plaintext_staging_cleaned", False),
            "source": self.state.get("source_identity"), "stages": self.state["stages"],
            "scope": "controlled_local_harbor_audit_not_leaderboard_or_M3_release_qualification"})

    def stage(self, name, operation):
        self.phase = name
        self.state["status"] = "running"
        self.state["stages"][name] = {"status": "running", "started_at": now()}
        self.save()
        self.publish_report()
        print(json.dumps({"stage": name, "status": "running"}), flush=True)
        result = operation()
        self.state["stages"][name].update(status="completed", finished_at=now(), result=result)
        self.save()
        self.publish_report()
        return result

    def command(self, command, timeout=300, env=None):
        # Subprocess inherits the workspace lock. SIGKILL of this controller
        # cannot cause another invocation to clean a still-running export.
        scratch = self.work.path / "scratch"
        scratch.mkdir(mode=0o700, exist_ok=True)
        output = scratch / "command-output.json"
        with output.open("wb") as stream:
            process = subprocess.Popen([str(x) for x in command], stdout=stream, stderr=subprocess.DEVNULL,
                                       env=env, start_new_session=True, pass_fds=self.child_lock_fds())
            try:
                code = process.wait(timeout=timeout)
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise
        if code:
            raise Failure(f"command_exit_{code}")
        return output

    def child_lock_fds(self):
        return (self.work.lock.fileno(),) + ((self.ledger.lock.fileno(),) if self.ledger else ())

    def admit_experiment(self):
        bound = self.state["config"]["experiment"]
        self.ledger = Ledger(Path(bound["ledger_path"]), self.a.experiment_plan, bound["plan_sha256"])
        try:
            self.ledger.__enter__()
        except BaseException:
            self.ledger = None
            raise
        config_sha256 = hashlib.sha256(json.dumps(self.state["config"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return self.ledger.reserve(bound["case_id"], self.work.path, config_sha256, self.state.get("launch_intent"))

    def preflight(self):
        if getattr(self.a, "task_network_subnet", None) and getattr(self.a, "experiment_plan", None):
            raise Failure("task_network_override_not_declared_by_M3_plan_schema")
        if getattr(self.a, "experiment_ledger", None) and not getattr(self.a, "experiment_plan", None):
            raise Failure("experiment_ledger_requires_bound_plan")
        if bool(getattr(self.a, "experiment_plan", None)) != bool(getattr(self.a, "experiment_case", None)) or (getattr(self.a, "experiment_plan", None) and not self.a.task):
            raise Failure("experiment_plan_and_case_require_fresh_task")
        if getattr(self.a, "recording_mode", "on") == "off" and not self.a.task:
            raise Failure("baseline_requires_fresh_task_or_same_workspace_resume")
        private_path(self.a.key_file)
        raw_key = self.a.key_file.read_bytes()
        if len(raw_key) != 32 and not re.fullmatch(rb"[0-9a-fA-F]{64}\s*", raw_key):
            raise Failure("invalid_recorder_key")
        config = {"source": str(self.a.from_trial or self.a.task), "model": self.a.model,
                  "api": self.a.api, "web": self.a.web, "agent_timeout": self.a.agent_timeout,
                  "verifier_timeout": getattr(self.a, "verifier_timeout", 300),
                  "iorec_sha256": digest(self.a.iorec), "key_fingerprint": hashlib.sha256(raw_key).hexdigest(),
                  "mode": "existing_trial" if self.a.from_trial else "fresh_trial"}
        if self.a.task:
            config["recording_mode"] = getattr(self.a, "recording_mode", "on")
        if self.a.task:
            config.update(agent=self.a.agent, upstream=self.a.upstream, agent_budget_usd=self.a.agent_budget_usd)
            # Match the profile's actual upload set, not a parallel hand-written
            # subset. A dependency change cannot silently reuse a paid trial.
            config["fresh_inputs"] = fresh_identity(self.a)
            if getattr(self.a, "experiment_plan", None):
                config["experiment"] = bind_case(self.a, config["fresh_inputs"])
            if getattr(self.a, "task_image", None):
                overlay = self.work.path / "task-image.compose.json"
                atomic_json(overlay, image_compose(self.a.task_image))
                config["task_image_compose"] = file_identity(overlay)
            if getattr(self.a, "task_network_subnet", None):
                overlay = self.work.path / "task-network.compose.json"
                atomic_json(overlay, network_compose(self.a.task_network_subnet))
                config["task_network_compose"] = file_identity(overlay)
            config["fresh_inputs_sha256"] = hashlib.sha256(
                json.dumps(config["fresh_inputs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
            launcher = config["fresh_inputs"]["harbor"]["launcher"]["path"]
            version_path = self.command([launcher, "--version"], timeout=30, env=harbor_environment())
            version = version_path.read_text().strip()
            if len(version) > 128 or not re.fullmatch(r"[A-Za-z0-9., +_-]+", version):
                raise Failure("unexpected_harbor_version_output")
            config["harbor_version"] = version
            config_path = self.work.path / "scratch/harbor-preflight-config.json"
            atomic_json(config_path, harbor_config(self.a, self.work.path))
            # Harbor returns before constructing a job in print-config mode.
            # Validate the installed schema without installing or running an agent.
            self.command([launcher, "run", "--config", config_path, "--print-config", "--yes"],
                         timeout=30, env=harbor_environment())
        previous = self.state.get("config")
        if previous and previous != config:
            raise Failure("workflow_inputs_changed_use_new_work_directory")
        self.state["config"] = config
        self.save()
        for origin, path, token in [(self.a.api, "/healthz", ""), (self.a.api, "/v1/system/health", self.token), (self.a.web, "/healthz", "")]:
            if api_request(origin, path, token).get("ok") is not True:
                raise Failure("platform_preflight_not_healthy")
        result = {k: v for k, v in config.items() if k.endswith("sha256") or k == "mode"}
        # No reallocation on evidence-only recovery of an existing trial.
        if getattr(self.a, "task_network_subnet", None) and not self.state.get("launch_intent"):
            result["task_network_preflight"] = probe_network(self.a.task_network_subnet)
        return result

    def assert_fresh_inputs(self):
        private_path(self.a.key_file)
        expected = self.state.get("config", {}).get("fresh_inputs")
        if not expected:
            raise Failure("fresh_trial_requires_current_input_preflight")
        current = fresh_identity(self.a, Path(expected["harbor"]["launcher"]["path"]))
        if current != expected or digest(self.a.key_file) != self.state["config"]["key_fingerprint"]:
            raise Failure("fresh_trial_inputs_changed_no_launch_or_qualification")
        if bind_case(self.a, current) != self.state["config"].get("experiment"):
            raise Failure("experiment_plan_changed_no_launch_or_qualification")
        if "task_image_compose" in self.state["config"]:
            overlay = self.work.path / "task-image.compose.json"
            private_path(overlay)
            if file_identity(overlay) != self.state["config"]["task_image_compose"]:
                raise Failure("task_image_overlay_changed_no_launch_or_qualification")
        if "task_network_compose" in self.state["config"]:
            overlay = self.work.path / "task-network.compose.json"
            private_path(overlay)
            if file_identity(overlay) != self.state["config"]["task_network_compose"]:
                raise Failure("task_network_overlay_changed_no_launch_or_qualification")

    def record(self):
        if self.a.from_trial:
            trial = self.a.from_trial
        else:
            job = self.work.path / "jobs/audit"
            completed = list(job.glob("*/result.json"))
            if self.state.get("launch_intent"):
                # Never resubmit a paid trial after an uncertain launch. A
                # terminal result is required; live children hold our lock.
                if len(completed) != 1 or not (job / "result.json").is_file():
                    raise Failure("prior_launch_incomplete_no_automatic_agent_retry")
            else:
                if job.exists():
                    raise Failure("unexpected_existing_harbor_job")
                self.assert_fresh_inputs()
                config_path = self.work.path / "harbor-config.json"
                atomic_json(config_path, harbor_config(self.a, self.work.path))
                env = harbor_environment()
                env.update(IOREC_HARBOR_BIN=str(self.a.iorec), IOREC_HARBOR_KEY_FILE=str(self.a.key_file),
                           IOREC_HARBOR_UPSTREAM=self.a.upstream,
                           IOREC_HARBOR_RECORDING_MODE=getattr(self.a, "recording_mode", "on"))
                if self.a.agent == "hermes":
                    env["IOREC_HARBOR_HERMES_BUNDLE"] = str(self.a.hermes_bundle)
                else:
                    env["IOREC_HARBOR_" + self.a.agent.upper() + "_BIN"] = str(getattr(self.a, self.a.agent))
                ledger_id = None
                if self.state["config"].get("experiment"):
                    if self.ledger is None:
                        raise Failure("bound_experiment_requires_ledger_admission")
                    ledger_id = self.ledger.mark_launch()
                self.state["launch_intent"] = {"at": now(), "agent_timeout_seconds": self.a.agent_timeout,
                                               "automatic_retries": 0}
                if self.state["config"].get("experiment"):
                    bound = self.state["config"]["experiment"]
                    self.state["launch_intent"]["ledger_reservation_id"] = ledger_id
                    self.state["launch_intent"]["experiment"] = {k: bound[k] for k in ("case_id", "plan_sha256")}
                self.save()
                launcher = self.state["config"]["fresh_inputs"]["harbor"]["launcher"]["path"]
                process = subprocess.Popen([launcher, "run", "--config", str(config_path), "--yes"],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                                           start_new_session=True, pass_fds=self.child_lock_fds())
                self.state["launch_intent"]["pid"] = process.pid
                self.save()
                # This is an observation deadline, not a new timeout imposed on
                # Docker or a reason to rerun. Harbor enforces the agent timeout.
                try:
                    code = process.wait(timeout=self.a.wait_seconds)
                except subprocess.TimeoutExpired:
                    raise Failure("harbor_still_running_observation_timeout_no_restart") from None
                self.state["launch_intent"]["exit_code"] = code
                self.save()
                completed = list(job.glob("*/result.json"))
            if len(completed) != 1:
                raise Failure("expected_exactly_one_harbor_trial")
            trial = completed[0].parent
            # A run may have spent minutes using live installation files. Drift
            # invalidates this qualification even when Harbor returned success;
            # keep its evidence and launch intent, and never auto-resubmit it.
            self.assert_fresh_inputs()
        benchmark, provenance = benchmark_from_trial(trial)
        self.state["trial_summary"] = {"benchmark": benchmark, **provenance}
        self.save()
        if self.state.get("config", {}).get("experiment"):
            expected = self.state["config"]["experiment"]["expected_result"]
            actual = {**benchmark, **provenance}
            if any(actual.get(key) != value for key, value in expected.items()):
                raise Failure("experiment_reported_trial_identity_mismatch")
        measurement = None
        auxiliary_measurements = []
        measurements = []
        mode = getattr(self.a, "recording_mode", "on")
        if self.a.task:
            try:
                measurements = measurement_definitions().read_trial_measurements(trial, mode)
                measurement, auxiliary_measurements = dominant_measurement(measurements)
            except (ValueError, OSError, TypeError, KeyError):
                raise Failure("fresh_trial_measurement_missing_or_invalid") from None
        else:
            measurement_root = trial / "agent/iorec-measurements"
            if measurement_root.exists() or measurement_root.is_symlink():
                try:
                    measurements = measurement_definitions().read_trial_measurements(trial, mode)
                    measurement, auxiliary_measurements = dominant_measurement(measurements)
                except (ValueError, OSError, TypeError, KeyError):
                    raise Failure("trial_measurement_invalid") from None
        runs = list((trial / "agent/iorec-runs").glob("run-*/manifest.json"))
        if mode == "off":
            if runs or any((trial / "agent/iorec-runs").iterdir() if (trial / "agent/iorec-runs").exists() else ()):
                raise Failure("baseline_unexpected_recording_artifacts")
            identity = {"benchmark": benchmark, "measurement": measurement, "recording_mode": "off"}
            if auxiliary_measurements:
                identity["measurement_selection"] = {
                    "policy": "unique_dominant_wall_seconds_at_least_4x",
                    "primary_invocation_id": measurement["invocation_id"],
                    "auxiliary_measurements": auxiliary_measurements,
                }
            if self.state.get("source_identity") not in (None, identity):
                raise Failure("source_evidence_changed")
            self.state["source_identity"] = identity
            self.save()
            return {**identity, **provenance, "fresh_trial": True, "fresh_inputs_unchanged": True,
                    "capture_qualification": "not_applicable_recorder_off"}
        if measurements:
            pairs = pair_measurements_and_captures(trial, measurements)
            selected_measurement, _ = dominant_measurement([pair["measurement"] for pair in pairs])
            selected = next(pair for pair in pairs if pair["measurement"]["invocation_id"] == selected_measurement["invocation_id"])
            run, manifest, measurement = selected["path"], selected["manifest"], selected["measurement"]
        else:
            if len(runs) != 1:
                raise Failure("expected_exactly_one_encrypted_capture_without_measurements")
            run = runs[0].parent
            manifest = read_json(runs[0])
            if manifest.get("status") != "finished" or not manifest.get("storage", {}).get("encryption"):
                raise Failure("capture_not_finished_and_encrypted")
            if not IDENTIFIER.fullmatch(manifest.get("run_id", "")) or run.name != manifest["run_id"]:
                raise Failure("invalid_capture_identifier")
            pairs, selected = [], None
        identity = {"run_id": manifest["run_id"], "manifest_sha256": digest(run / "manifest.json"),
                    "events_sha256": digest(run / "events.jsonl"), "benchmark": benchmark}
        if measurement is not None:
            identity["measurement"] = measurement
        auxiliary_captures = []
        for pair in pairs:
            if pair is selected:
                continue
            auxiliary_captures.append({
                "run_id": pair["manifest"]["run_id"],
                "manifest_sha256": digest(pair["path"] / "manifest.json"),
                "events_sha256": digest(pair["path"] / "events.jsonl"),
                "measurement": pair["measurement"],
            })
        if auxiliary_captures:
            identity["capture_selection"] = {
                "policy": "unique_dominant_wall_seconds_at_least_4x",
                "primary_invocation_id": measurement["invocation_id"],
                "capture_count": len(pairs),
                "auxiliary_captures": auxiliary_captures,
            }
        if self.state.get("source_identity") not in (None, identity):
            raise Failure("source_evidence_changed")
        self.state["source_identity"] = identity
        self.state["run_path"] = str(run)
        self.save()
        return {**identity, **provenance, "fresh_trial": not bool(self.a.from_trial),
                "fresh_inputs_unchanged": True if self.a.task else None}

    def integrity(self):
        report = read_json(self.command([self.a.iorec, "verify", "--profile", "integrity", "--json",
                                        "--key-file", self.a.key_file, self.state["run_path"]]))
        if report.get("passed") is not True:
            raise Failure("integrity_verification_failed")
        return {"passed": True, "profile": "integrity", "checks": len(report.get("checks", []))}

    def audit(self):
        output = self.work.path / "scratch/transport.json"
        self.command([self.a.iorec, "transport-audit", "--key-file", self.a.key_file,
                      "--output", output, self.state["run_path"]], timeout=360)
        report = read_json(output)
        summary = {k: report.get(k) for k in ("schema_version", "complete", "payload_diff_passed", "completeness_boundary",
                   "matched_attempts", "missing_from_wire", "extra_on_wire", "websocket_rows", "manifest_capture_drops")}
        summary["gaps_count"] = len(report.get("gaps", []))
        summary["decoder_sha256"] = report.get("tshark", {}).get("sha256")
        if report.get("complete") is not True or report.get("payload_diff_passed") is not True or summary["gaps_count"]:
            raise Failure("independent_transport_audit_incomplete")
        return summary

    def import_run(self):
        bundle = self.work.path / "scratch/bundle.tar"
        try:
            self.command([self.a.iorec, "export", "--format", "platform", "--key-file", self.a.key_file,
                          "--output", bundle, self.state["run_path"]], timeout=600)
            private_path(bundle)
            result = api_request(self.a.api, "/v1/recordings:import", self.token, method="POST", bundle=bundle)
            if result.get("capture_run_id") != self.state["source_identity"]["run_id"] or result.get("sealed") is not True:
                raise Failure("import_identity_or_seal_mismatch")
            return {k: result.get(k) for k in ("capture_run_id", "recording_id", "sealed", "events", "blobs", "durable_seq")}
        finally:
            # Covers export/import errors as well as success. A SIGKILL leaves
            # private scratch, which is removed under the lock on next resume.
            self.work.cleanup()

    def qualify_platform(self):
        run = self.state["source_identity"]["run_id"]
        rec = self.state["stages"]["import"]["result"]["recording_id"]
        benchmark = self.state["source_identity"]["benchmark"]
        api_request(self.a.api, "/v1/capture-runs/"+quote(run, safe="")+"/benchmark-result",
                    self.token, method="PUT", value=benchmark)
        deadline = time.monotonic() + self.a.wait_seconds
        while True:
            data = api_request(self.a.api, "/v1/recordings/"+quote(rec, safe=""), self.token)
            if data.get("failed_jobs", 0):
                raise Failure("platform_processing_jobs_failed")
            proof = data.get("transport_proof") or {}
            if not data.get("active_jobs", 0) and data.get("coverage") and proof.get("status"):
                if proof.get("verified") is not True or proof.get("payload_diff_passed") is not True or proof.get("source_boundary_verified") is not True:
                    raise Failure("platform_independent_proof_not_verified")
                return {"transport_proof_status": proof["status"], "processor_version": proof.get("processor_version"),
                        "coverage_claim": data["coverage"].get("claim"), "inferences": data.get("inference_count"),
                        "benchmark_provenance": (data.get("benchmark_result") or {}).get("provenance"),
                        "recording_url": self.a.web+"/recordings/"+quote(rec, safe="")}
            if time.monotonic() >= deadline:
                raise Failure("platform_processing_observation_timeout_resume_same_workflow")
            time.sleep(2)

    def run(self):
        self.experiment_control = None
        self.work.cleanup()
        # A revalidation in progress must not retain a prior green report.
        self.state.update(status="running", stages={}, plaintext_staging_cleaned=False)
        self.save()
        self.publish_report()
        try:
            self.stage("preflight", self.preflight)
            if self.a.preflight_only:
                self.state["status"] = "preflight_only"
                return
            if self.state.get("config", {}).get("experiment"):
                self.stage("admission", self.admit_experiment)
            self.stage("record", self.record)
            if getattr(self.a, "recording_mode", "on") == "off":
                self.state["status"] = "baseline_completed"
                return
            self.stage("integrity", self.integrity)
            self.stage("transport_audit", self.audit)
            self.stage("import", self.import_run)
            self.stage("platform", self.qualify_platform)
            self.state["status"] = "completed"
        except BaseException as error:
            code = str(error) if isinstance(error, (Failure, InputFailure, PlanFailure, LedgerFailure, NetworkFailure)) else type(error).__name__
            self.state["stages"].setdefault(self.phase, {}).update(status="failed", error=code, finished_at=now())
            self.state["status"] = "incomplete"
            raise
        finally:
            try:
                self.work.cleanup()
                self.state["plaintext_staging_cleaned"] = True
                self.save()
                self.publish_report()
                if self.ledger and self.ledger.active:
                    self.experiment_control = self.ledger.settle(self.state, digest(self.work.path / "report.json"))
            finally:
                if self.ledger:
                    self.ledger.__exit__()
                    self.ledger = None


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work-dir", type=Path, required=True)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--task", type=Path)
    source.add_argument("--from-trial", type=Path)
    p.add_argument("--model", default="")
    p.add_argument("--experiment-plan", type=Path, help="bind a fully declared M3 plan before launch; not user approval or a global spending guard")
    p.add_argument("--experiment-case", help="exact case ID from --experiment-plan; required together")
    p.add_argument("--experiment-ledger", type=Path, help="shared private admission directory; defaults to PLAN_FILE.ledger, not a provider-side billing cap")
    p.add_argument("--recording-mode", choices=("on", "off"), default="on",
                   help="off is a measured native-network baseline, never capture-qualified or imported")
    p.add_argument("--agent", choices=("codex", "claude", "hermes"), default="codex")
    p.add_argument("--upstream", default="", help="explicit non-loopback HTTPS provider endpoint; defaults to the agent's native provider")
    p.add_argument("--agent-budget-usd", type=float, help="Claude's native per-run budget flag; not a cross-agent or provider-side hard cap")
    p.add_argument("--preflight-only", action="store_true",
                   help="check and pin fresh-trial inputs and platform health; never launch an agent")
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--iorec", type=Path, default=ROOT / "target/release/iorec")
    p.add_argument("--codex", type=Path, default=Path(shutil.which("codex") or "/missing/codex"))
    p.add_argument("--claude", type=Path, default=Path(shutil.which("claude") or "/missing/claude"))
    p.add_argument("--hermes-bundle", type=Path, help="verified installed Hermes/Python archive; required for fresh Hermes trials")
    p.add_argument("--task-image", help="locally available repository@sha256 digest matching the task image; single-service/shared-verifier tasks only")
    p.add_argument("--task-network-subnet", help="optional task-scoped RFC1918 IPv4 /24 through /28; preflight creates/removes its own empty probe network, never prunes existing networks")
    p.add_argument("--api", default="http://127.0.0.1:18080")
    p.add_argument("--web", default="http://127.0.0.1:8088")
    p.add_argument("--token-file", type=Path)
    p.add_argument("--agent-timeout", type=int, default=900)
    p.add_argument("--verifier-timeout", type=int, default=300, help="explicit verifier limit; use the pinned task's value for benchmark-comparable runs")
    p.add_argument("--wait-seconds", type=int, default=3600, help="observation deadline; never automatically reruns an agent")
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        args.api, args.web = local_url(args.api), local_url(args.web)
        for key in ("task", "from_trial", "iorec", "codex", "claude", "hermes_bundle", "key_file", "token_file", "experiment_plan", "experiment_ledger"):
            if getattr(args, key):
                setattr(args, key, getattr(args, key).absolute())
        # Preserve strict ownership checks on the key, but resolve CLI symlinks
        # so the adjacent code-mode-host is the actual installed helper.
        args.codex = args.codex.resolve()
        args.claude = args.claude.resolve()
        definitions = audit_definitions()
        try:
            args.upstream = definitions.upstream_url(args.upstream or definitions.AGENTS[args.agent]["upstream"])
        except ValueError:
            raise Failure("fresh_trial_requires_non_loopback_https_upstream") from None
        if args.agent_budget_usd is not None and (args.agent != "claude" or not math.isfinite(args.agent_budget_usd) or args.agent_budget_usd <= 0):
            raise Failure("positive_claude_only_agent_budget_required")
        if not 1 <= args.agent_timeout <= 3600 or not 1 <= args.verifier_timeout <= 3600 or not 1 <= args.wait_seconds <= 86400:
            raise Failure("invalid_timeout")
        provider = definitions.AGENTS[args.agent]["provider"]
        if args.task and (not IDENTIFIER.fullmatch(args.model) or not args.model.startswith(provider + "/")
                          or not args.model[len(provider) + 1:] or not (args.task / "task.toml").is_file()):
            raise Failure("fresh_trial_requires_model_and_harbor_task")
        if args.preflight_only and not args.task:
            raise Failure("preflight_only_requires_fresh_task")
        if args.task_image and not args.task:
            raise Failure("task_image_override_requires_fresh_task")
        if args.task_network_subnet and not args.task:
            raise Failure("task_network_override_requires_fresh_task")
        if args.task and args.agent == "hermes" and not args.hermes_bundle:
            raise Failure("fresh_hermes_trial_requires_pinned_runtime_bundle")
        with Workspace(args.work_dir) as work:
            workflow = Workflow(args, work)
            workflow.run()
        print(json.dumps({"status": workflow.state["status"],
                          "experiment_control": workflow.experiment_control,
                          "report": str(args.work_dir.absolute() / "report.json")}))
        return 2 if workflow.experiment_control and workflow.experiment_control["stop_further_paid_trials"] else 0
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps({"status": "incomplete", "error": str(error) if isinstance(error, (Failure, InputFailure, PlanFailure, LedgerFailure, NetworkFailure)) else type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
