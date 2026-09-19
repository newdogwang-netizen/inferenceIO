#!/usr/bin/env python3
"""Compare completed, predeclared Harbor off/on observations without launching.

Reads private workflow workspaces under shared locks. Does not contact providers,
rerun capture audits, certify billing, or establish causal recorder overhead.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import copy
import datetime as dt
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace

import harbor_audit_workflow as workflow
from harbor_input_provenance import audit_definitions, measurement_definitions, file_identity
from m3_experiment_plan import validate


class ComparisonFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise ComparisonFailure(code)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def digest(path):
    return file_identity(path)["sha256"]


def artifact(root: Path, relative: str):
    path = root
    for part in Path(relative).parts:
        require(part not in ("..", "/"), "artifact_path_outside_workflow")
        path = path / part
        require(not path.is_symlink(), "symlink_artifact_rejected")
    return path


def json_file(path: Path, *, with_digest=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as src:
        require(stat.S_ISREG(os.fstat(src.fileno()).st_mode), "artifact_not_regular")
        raw = src.read((8 << 20) + 1)
    require(len(raw) <= 8 << 20, "comparison_json_too_large")
    value = json.loads(raw)
    require(isinstance(value, dict), "comparison_json_not_object")
    return (value, hashlib.sha256(raw).hexdigest()) if with_digest else value


@contextmanager
def locked(root: Path):
    workflow.private_path(root, directory=True)
    path = root / ".lock"
    workflow.private_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ComparisonFailure("workflow_or_child_still_running") from None
        yield


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40, "invalid_trial_timestamp")
    parsed = dt.datetime.fromisoformat(value)
    require(parsed.utcoffset() is not None, "trial_timestamp_requires_timezone")
    return parsed


def duration(stage):
    require(isinstance(stage, dict), "missing_actual_trial_stage")
    elapsed = (timestamp(stage.get("finished_at")) - timestamp(stage.get("started_at"))).total_seconds()
    require(0 <= elapsed <= 86400, "invalid_trial_stage_duration")
    return elapsed


def terminal_job_time(job, trial, intent):
    """Never silently interpret Harbor's naive job wall clock as UTC."""
    finish = job.get("finished_at")
    require(isinstance(finish, str) and len(finish) <= 40, "invalid_trial_timestamp")
    parsed = dt.datetime.fromisoformat(finish)
    if parsed.utcoffset() is not None:
        require(parsed >= timestamp(trial.get("finished_at")), "harbor_job_not_terminal_after_trial")
        return "timezone_aware_job_and_trial"
    # Harbor 0.22 job.py uses datetime.now(), while trial/observer timestamps
    # are aware. Check that local interval without converting clock domains.
    # A waited successful process plus terminal progress counters supplies the
    # job-termination evidence; serial order still uses aware trial times.
    start = job.get("started_at")
    require(isinstance(start, str) and len(start) <= 40, "invalid_trial_timestamp")
    start = dt.datetime.fromisoformat(start)
    require(start.utcoffset() is None and 0 <= (parsed - start).total_seconds() <= 86400,
            "invalid_local_job_interval")
    expected = {"n_completed_trials": 1, "n_errored_trials": 0, "n_running_trials": 0,
                "n_pending_trials": 0, "n_cancelled_trials": 0, "n_retries": 0}
    stats = job.get("stats") or {}
    require(type(intent.get("exit_code")) is int and intent["exit_code"] == 0
            and type(job.get("n_total_trials")) is int and job["n_total_trials"] == 1
            and all(type(stats.get(k)) is int and stats[k] == v for k, v in expected.items()),
            "naive_job_time_requires_successful_terminal_process_and_counters")
    return "local_job_clock_not_cross_compared_aware_trial_order_and_waited_exit"


def read_case(root, mode, plan, plan_sha256):
    state_path, report_path = root / "state.json", root / "report.json"
    workflow.private_path(state_path)
    workflow.private_path(report_path)
    state, report = json_file(state_path), json_file(report_path)
    status = "baseline_completed" if mode == "off" else "completed"
    require(state.get("status") == report.get("workflow_status") == status, "workflow_not_completed")
    require(report.get("recording_mode") == mode and report.get("qualification_passed") is (mode == "on")
            and report.get("baseline_completed") is (mode == "off"), "workflow_mode_or_claim_mismatch")
    require(state.get("plaintext_staging_cleaned") is True and report.get("plaintext_staging_cleaned") is True
            and not (root / "scratch").exists(), "workflow_cleanup_not_complete")
    for a, b in (("source_identity", "source"), ("stages", "stages"), ("trial_summary", "trial_summary")):
        require(state.get(a) == report.get(b) and isinstance(state.get(a), dict), "state_report_disagree")
    stages = state["stages"]
    expected_stages = {"preflight", "admission", "record"} if mode == "off" else {"preflight", "admission", "record", "integrity", "transport_audit", "import", "platform"}
    require(set(stages) == expected_stages and all(v.get("status") == "completed" for v in stages.values()), "missing_completed_workflow_stages")
    recorded = stages["record"]["result"]
    require(recorded.get("fresh_trial") is True and recorded.get("fresh_inputs_unchanged") is True, "pair_requires_fresh_inputs")
    cfg = copy.deepcopy(state["config"])
    require(set(cfg) == set("agent agent_budget_usd agent_timeout api experiment fresh_inputs fresh_inputs_sha256 harbor_version iorec_sha256 key_fingerprint mode model recording_mode source task_image_compose upstream verifier_timeout web".split()), "unsupported_workflow_config_shape")
    require(cfg.get("mode") == "fresh_trial" and cfg.get("recording_mode") == mode, "pair_requires_fresh_inputs")
    fresh = cfg["fresh_inputs"]
    fresh_keys = set("agent cli_wrapper_sha256 controller harbor recording_mode task task_image_override uploads upstream".split())
    if cfg["agent"] == "hermes":
        fresh_keys.add("hermes_runtime")
    require(set(fresh) == fresh_keys and bool(fresh["controller"]) and bool(fresh["harbor"]), "missing_input_provenance")
    require(canonical_hash(fresh) == cfg.get("fresh_inputs_sha256"), "fresh_inputs_digest_mismatch")
    require(stages["preflight"]["result"].get("fresh_inputs_sha256") == cfg["fresh_inputs_sha256"]
            and stages["preflight"]["result"].get("iorec_sha256") == cfg["iorec_sha256"]
            and stages["preflight"]["result"].get("mode") == "fresh_trial", "preflight_result_differs_from_inputs")
    intent = state.get("launch_intent") or {}
    require(type(intent.get("pid")) is int and intent["pid"] > 0
            and type(intent.get("automatic_retries")) is int and intent["automatic_retries"] == 0,
            "missing_single_launch_provenance")
    binding = cfg["experiment"]
    require(set(binding) == {"case_id", "plan_path", "plan_sha256", "expected_result", "ledger_path"}
            and binding.get("case_id") == "paired-" + mode and binding.get("plan_sha256") == plan_sha256
            and intent.get("experiment") == {"case_id": binding["case_id"], "plan_sha256": plan_sha256},
            "plan_not_bound_to_launch")
    require(isinstance(binding["ledger_path"], str) and Path(binding["ledger_path"]).is_absolute()
            and isinstance(intent.get("ledger_reservation_id"), str) and len(intent["ledger_reservation_id"]) == 32
            and intent["ledger_reservation_id"] == stages["admission"]["result"].get("reservation_id"), "ledger_admission_not_bound_to_launch")
    pair = plan["paired"]
    agent = plan["agents"][pair["agent"]]
    task = next(t for t in plan["tasks"] if t["id"] == pair["task"])
    require(binding["expected_result"] == {"agent": {"codex": "codex", "claude": "claude-code", "hermes": "hermes"}[pair["agent"]],
            "agent_version": agent["version"], "model": agent["model"],
            "task": fresh["task"].get("harbor_name", task["id"])}, "launch_identity_differs_from_plan")
    require(cfg.get("agent") == fresh.get("agent") == pair["agent"]
            and cfg.get("model") == agent["model"] and cfg.get("upstream") == fresh.get("upstream") == agent["upstream"]
            and cfg.get("source") == task["path"] and cfg.get("iorec_sha256") == plan["recorder"]["sha256"]
            and cfg.get("agent_timeout") == plan["limits"]["agent_timeout_seconds"]
            and cfg.get("verifier_timeout") == plan["limits"]["verifier_timeout_seconds"], "case_differs_from_declared_pair")
    remote = "/tmp/iorec-hermes-runtime.tar.gz" if pair["agent"] == "hermes" else "/opt/iorec-agent/" + pair["agent"]
    require(fresh["uploads"][remote]["sha256"] == agent["artifact"]["sha256"]
            and fresh["uploads"]["/tmp/iorec-bin"]["sha256"] == cfg["iorec_sha256"]
            and fresh["task"]["sha256"] == task["source_tree_sha256"]
            and fresh["task_image_override"]["pinned_reference"] == task["image"], "case_artifacts_differ_from_plan")
    require(fresh.get("recording_mode") == mode, "input_recording_mode_mismatch")
    # This checkout must understand exactly the wrapper and observer being compared.
    expected_wrapper = audit_definitions().cli_wrapper(pair["agent"], agent["upstream"], mode)
    require(fresh.get("cli_wrapper_sha256") == hashlib.sha256(expected_wrapper.encode()).hexdigest()
            and fresh["uploads"]["/opt/iorec-agent/measure.py"]["sha256"] == digest(workflow.ROOT / "examples/harbor_audit_measure.py"),
            "comparison_requires_matching_wrapper_and_observer_revision")
    overlay = artifact(root, "task-image.compose.json")
    require(digest(overlay) == cfg["task_image_compose"]["sha256"], "task_overlay_changed")
    require(json_file(overlay) == {"services": {"main": {"image": task["image"], "pull_policy": "never"}}}, "task_overlay_not_pinned")
    arguments = SimpleNamespace(agent=cfg["agent"], model=cfg["model"], agent_timeout=cfg["agent_timeout"],
                                verifier_timeout=cfg["verifier_timeout"], agent_budget_usd=cfg["agent_budget_usd"],
                                task=Path(cfg["source"]), task_image=task["image"])
    launched = json_file(artifact(root, "harbor-config.json"))
    require(launched == workflow.harbor_config(arguments, root)
            and launched["agents"][0]["override_setup_timeout_sec"] == plan["limits"]["setup_timeout_seconds"],
            "harbor_launch_configuration_differs")
    benchmark = state["source_identity"]["benchmark"]
    require(isinstance(benchmark.get("trial"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.~-]{0,255}", benchmark["trial"]), "unsafe_trial_identifier")
    trial = artifact(root, "jobs/audit/" + benchmark["trial"])
    job = trial.parent
    job_result = json_file(artifact(job, "result.json"))
    completed = []
    with os.scandir(job) as entries:
        for count, entry in enumerate(entries):
            require(count < 128, "unexpected_harbor_job_contents")
            require(not entry.is_symlink(), "symlink_artifact_rejected")
            if entry.is_dir() and (Path(entry.path) / "result.json").exists():
                completed.append(entry.name)
    require(completed == [benchmark["trial"]], "pair_requires_exactly_one_terminal_trial_per_job")
    result = json_file(artifact(trial, "result.json"))
    job_time_basis = terminal_job_time(job_result, result, intent)
    actual, provenance = workflow.benchmark_from_trial(trial)
    require(actual == benchmark and state["trial_summary"] == {"benchmark": actual, **provenance}, "trial_result_changed")
    require(all(recorded.get(k) == v for k, v in {**state["source_identity"], **provenance}.items()), "record_stage_differs_from_source")
    require(actual["task"] == fresh["task"].get("harbor_name", task["id"]) and actual["model"] == agent["model"]
            and actual["agent"] == {"codex": "codex", "claude": "claude-code", "hermes": "hermes"}[pair["agent"]]
            and provenance["agent_version"] == agent["version"], "reported_trial_identity_differs_from_plan")
    timing = {name: duration(result.get(name)) for name in ("environment_setup", "agent_setup", "agent_execution", "verifier")}
    metrics = measurement_definitions().read_trial_measurement(trial, mode)
    require(metrics == state["source_identity"].get("measurement") == recorded.get("measurement"), "measurement_artifact_changed")
    require(timestamp(result["agent_execution"]["started_at"]) <= timestamp(metrics["started_at"])
            <= timestamp(result["agent_execution"]["finished_at"]), "measurement_outside_agent_execution")
    inventories = {name: digest(artifact(trial, "agent/" + name)) for name in ("audit-package-inventory.tsv", "audit-tool-sha256.txt")}
    captures = artifact(trial, "agent/iorec-runs")
    if mode == "off":
        require(not captures.exists() or (captures.is_dir() and next(captures.iterdir(), None) is None), "baseline_has_capture_artifacts")
        require("run_id" not in state["source_identity"], "baseline_has_capture_identity")
    else:
        source = state["source_identity"]
        require(isinstance(source.get("run_id"), str) and re.fullmatch(r"run-[A-Za-z0-9-]{1,128}", source["run_id"]), "unsafe_capture_identifier")
        run = artifact(captures, source["run_id"])
        require(digest(artifact(run, "manifest.json")) == source["manifest_sha256"]
                and digest(artifact(run, "events.jsonl")) == source["events_sha256"], "capture_index_changed_since_audit")
        require(stages["integrity"]["result"].get("passed") is True
                and stages["transport_audit"]["result"].get("complete") is True
                and stages["transport_audit"]["result"].get("payload_diff_passed") is True
                and type(stages["transport_audit"]["result"].get("gaps_count")) is int
                and stages["transport_audit"]["result"].get("gaps_count") == 0
                and stages["import"]["result"].get("capture_run_id") == source["run_id"]
                and stages["import"]["result"].get("sealed") is True
                and stages["platform"]["result"].get("transport_proof_status") == "verified", "recorded_workflow_proof_missing")
    # Only expected per-workspace/mode differences are removed. All other inputs,
    # including full upload/controller/runtime identities and timeouts, must match.
    del cfg["recording_mode"], cfg["fresh_inputs_sha256"]
    del cfg["experiment"]["case_id"]
    del fresh["recording_mode"], fresh["cli_wrapper_sha256"]
    del cfg["task_image_compose"]["path"]
    return {"common": cfg, "inventory": inventories, "started": timestamp(result["started_at"]),
            "finished": timestamp(result["finished_at"]), "summary": {
                "workflow_report_sha256": digest(report_path), "benchmark": benchmark, **provenance,
                "measurement": metrics, "harbor_stage_seconds": timing,
                "job_time_basis": job_time_basis,
                "installed_inventory_sha256": inventories}}


def compare(off: Path, on: Path, plan_path: Path):
    plan, plan_sha256 = json_file(plan_path, with_digest=True)
    declaration = validate(plan)
    require(declaration["declaration_complete"], "comparison_requires_complete_predeclared_plan")
    roots = {"off": off.absolute(), "on": on.absolute()}
    require(roots["off"].resolve() != roots["on"].resolve(), "pair_requires_distinct_workspaces")
    with ExitStack() as stack:
        for root in sorted(roots.values()):
            stack.enter_context(locked(root))
        cases = {mode: read_case(root, mode, plan, plan_sha256) for mode, root in roots.items()}
        require(cases["off"]["common"] == cases["on"]["common"], "pair_inputs_differ")
        require(cases["off"]["inventory"] == cases["on"]["inventory"], "installed_packages_or_tools_differ")
        require(cases["off"]["summary"]["measurement"]["observer_python_version"] == cases["on"]["summary"]["measurement"]["observer_python_version"], "observer_runtime_versions_differ")
        first, second = plan["paired"]["order"]
        require(cases[first]["started"] <= cases[first]["finished"] <= cases[second]["started"] <= cases[second]["finished"], "pair_order_or_serial_execution_mismatch")
        metrics = {}
        for name in ("wall_seconds", "user_cpu_seconds", "system_cpu_seconds", "max_rss_kib"):
            a, b = (cases[mode]["summary"]["measurement"][name] for mode in ("off", "on"))
            metrics[name] = {"off": a, "on": b, "on_minus_off": b - a, "on_divided_by_off": b / a if a else None}
        costs = {mode: case["summary"]["reported_cost_usd"] for mode, case in cases.items()}
        cost_ok = all(cost is not None and Decimal(str(cost)) <= Decimal(plan["budget"]["per_trial_usd"]) for cost in costs.values())
        return {"schema_version": 1, "generated_at": workflow.now(), "paired_metrics_compared": True,
                "qualification_passed": False, "m3_complete": False, "plan_sha256": plan_sha256,
                "common_inputs_sha256": canonical_hash(cases["off"]["common"]), "declared_order": plan["paired"]["order"],
                "cases": {mode: case["summary"] for mode, case in cases.items()}, "metric_comparison": metrics,
                "reported_costs_within_per_trial_limit": cost_ok, "stop_further_paid_trials": not cost_ok,
                "billing_verified": False, "network_dependency_impact": "not_determined_from_summary",
                "scope": "consistent_completed_workflow_observations_not_crypto_reaudit_or_causal_overhead",
                "limitations": ["Recorder-on adds network/capability confinement; off retains native container networking.",
                    "Single-pair order effects, model nondeterminism and external dependency failures need separate interpretation.",
                    "Naive Harbor job times are not treated as UTC; trial/observer ordering uses aware timestamps and terminal process/counter evidence.",
                    "RSS is the largest individual process peak including possible pre-exec memory, not simultaneous tree memory.",
                    "Existing workflow proof and current index hashes are checked; encrypted blobs and network proof are not re-audited here.",
                    "Harbor-reported costs are not provider billing evidence or enforcement of the total matrix budget."]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--off-work-dir", type=Path, required=True)
    p.add_argument("--on-work-dir", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--output", type=Path, help="new file in an existing private directory, outside both evidence workspaces")
    args = p.parse_args()
    try:
        if args.output:
            workflow.private_path(args.output.parent, directory=True)
            require(not args.output.exists() and not args.output.is_symlink(), "comparison_output_must_be_new")
            require(not any(args.output.resolve().is_relative_to(root.resolve()) for root in (args.off_work_dir, args.on_work_dir)), "output_must_not_modify_evidence_workspace")
        result = compare(args.off_work_dir, args.on_work_dir, args.plan)
        if args.output:
            measurement_definitions().publish(args.output.parent, args.output.name, result)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0 if result["reported_costs_within_per_trial_limit"] else 2
    except Exception as error:
        print(json.dumps({"paired_metrics_compared": False, "qualification_passed": False,
                          "error": str(error) if isinstance(error, ComparisonFailure) else type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
