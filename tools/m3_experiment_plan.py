#!/usr/bin/env python3
"""Validate the full M3 declaration without installing/running any agent.

This tool never grants spending authority or enforces a provider billing cap.
--require-approved fails closed unless every model, budget and operator evidence
reference is filled in, and local input hashes/images match. An evidence hash is
an operator assertion, not a provider-side attestation. No paid launcher exists
in this utility; use the declared one-case workflow only after actual approval.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import sys

from harbor_input_provenance import audit_definitions, file_identity, pinned_image_reference, task_image_input, tree_identity


class PlanFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise PlanFailure(code)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), "unexpected_plan_fields")


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_plan_digest")


def artifact(value):
    fields(value, "path sha256")
    require(isinstance(value["path"], str) and Path(value["path"]).is_absolute(), "plan_requires_absolute_input_paths")
    sha(value["sha256"])


def money(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,6})?", value), "money_requires_positive_decimal_string")
    result = Decimal(value)
    require(result > 0, "money_requires_positive_decimal_string")
    return result


def reference(value):
    require(isinstance(value, str) and 1 <= len(value) <= 256
            and value.strip() == value and not any(c in value for c in "\r\n\x00"),
            "approval_reference_required")


def validate(plan, verify_local=False):
    require(isinstance(plan, dict), "unexpected_plan_fields")
    amended = type(plan.get("schema_version")) is int and plan["schema_version"] == 2
    fields(plan, "schema_version kind dataset recorder agents tasks repetitions paired limits budget"
           + (" scope_amendment" if amended else ""))
    require(type(plan["schema_version"]) is int and plan["schema_version"] in (1, 2)
            and plan["kind"] == "iorec-m3-real-experiment-plan", "unsupported_plan_schema")
    if amended:
        fields(plan["scope_amendment"], "excluded_agents approval_reference")
        require(plan["scope_amendment"]["excluded_agents"] == ["claude"], "explicit_claude_exclusion_required")
        reference(plan["scope_amendment"]["approval_reference"])
    fields(plan["dataset"], "name content_sha256 task_count registry_checked_on")
    require(plan["dataset"]["name"] == "terminal-bench/terminal-bench-2"
            and plan["dataset"]["task_count"] == 89, "plan_requires_explicit_terminal_bench_2_snapshot")
    sha(plan["dataset"]["content_sha256"])
    require(isinstance(plan["dataset"]["registry_checked_on"], str)
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", plan["dataset"]["registry_checked_on"]), "registry_check_date_required")
    artifact(plan["recorder"])
    definitions = audit_definitions()
    expected_agents = {"codex", "hermes"} if amended else {"codex", "claude", "hermes"}
    require(isinstance(plan["agents"], dict) and set(plan["agents"]) == expected_agents,
            "amended_plan_requires_codex_and_hermes" if amended else "all_three_agents_required")
    missing = []
    for name, agent in plan["agents"].items():
        fields(agent, "version model upstream artifact")
        artifact(agent["artifact"])
        require(isinstance(agent["version"], str) and re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,63}", agent["version"]), "explicit_agent_version_required")
        definitions.upstream_url(agent["upstream"])
        if agent["model"] is None:
            missing.append("model:" + name)
        else:
            require(isinstance(agent["model"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@+~-]{0,255}", agent["model"])
                    and agent["model"].startswith(definitions.AGENTS[name]["provider"] + "/")
                    and len(agent["model"].split("/", 1)[1]) > 0, "model_provider_mismatch")
            require(not any(s in agent["model"].lower() for s in ("placeholder", "your_model")), "placeholder_model_not_approved")
    tasks = plan["tasks"]
    require(isinstance(tasks, list) and len(tasks) == 2, "exactly_two_representative_tasks_required")
    ids = []
    for task in tasks:
        fields(task, "id path package_sha256 source_tree_sha256 image category")
        require(isinstance(task["id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", task["id"]), "invalid_task_id")
        require(isinstance(task["path"], str) and Path(task["path"]).is_absolute(), "plan_requires_absolute_input_paths")
        sha(task["package_sha256"])
        sha(task["source_tree_sha256"])
        require(isinstance(task["category"], str) and bool(task["category"]), "task_category_required")
        pinned_image_reference(task["image"])
        ids.append(task["id"])
    require(len(set(ids)) == 2, "duplicate_task")
    require(len({t["category"] for t in tasks}) == 2, "two_task_categories_required")
    require(type(plan["repetitions"]) is int and plan["repetitions"] == 2, "two_repetitions_required")
    fields(plan["paired"], "agent task order")
    pair = plan["paired"]
    require(pair["agent"] in plan["agents"] and pair["task"] in ids
            and isinstance(pair["order"], list) and len(pair["order"]) == 2
            and set(pair["order"]) == {"off", "on"}, "additional_on_off_pair_required")
    fields(plan["limits"], "agent_timeout_seconds verifier_timeout_seconds setup_timeout_seconds concurrency automatic_retries stop_on_recording_gap stop_on_unclassified_failure stop_on_unknown_or_exceeded_cost preserve_failed_trials")
    limits = plan["limits"]
    for name in ("agent_timeout_seconds", "verifier_timeout_seconds", "setup_timeout_seconds"):
        require(type(limits[name]) is int and 1 <= limits[name] <= 3600, "bounded_timeouts_required")
    require(type(limits["concurrency"]) is int and limits["concurrency"] == 1
            and type(limits["automatic_retries"]) is int and limits["automatic_retries"] == 0,
            "serial_execution_without_automatic_retries_required")
    require(all(limits[name] is True for name in ("stop_on_recording_gap", "stop_on_unclassified_failure",
            "stop_on_unknown_or_exceeded_cost", "preserve_failed_trials")), "fail_closed_stop_policy_required")
    fields(plan["budget"], "currency total_usd per_trial_usd approval_reference provider_cap_evidence_sha256"
           + (" provider_cap_waiver" if amended else ""))
    budget = plan["budget"]
    waiver = budget.get("provider_cap_waiver")
    if waiver is not None:
        fields(waiver, "approval_reference reason")
        reference(waiver["approval_reference"])
        reference(waiver["reason"])
        require(budget["provider_cap_evidence_sha256"] is None, "waiver_is_not_provider_cap_evidence")
    require(budget["currency"] == "USD", "budget_currency_must_be_explicit_usd")
    for name in ("total_usd", "per_trial_usd", "approval_reference", "provider_cap_evidence_sha256"):
        if budget[name] is None:
            if name != "provider_cap_evidence_sha256" or waiver is None:
                missing.append("budget:" + name)
        elif name.endswith("usd"):
            money(budget[name])
        elif name.endswith("sha256"):
            sha(budget[name])
        else:
            reference(budget[name])
    matrix_trials = len(expected_agents) * len(tasks) * plan["repetitions"]
    if budget["total_usd"] is not None and budget["per_trial_usd"] is not None:
        require(money(budget["total_usd"]) >= (matrix_trials + 2) * money(budget["per_trial_usd"]),
                "budget_must_cover_eight_trials_plus_two_paired_runs" if amended
                else "budget_must_cover_twelve_trials_plus_two_paired_runs")
    if verify_local:
        for value in [plan["recorder"], *[a["artifact"] for a in plan["agents"].values()]]:
            require(file_identity(Path(value["path"]))["sha256"] == value["sha256"], "local_runtime_digest_changed")
        for task in tasks:
            require(tree_identity(Path(task["path"]), ignored_names=(".git",))["sha256"] == task["source_tree_sha256"], "local_task_tree_changed")
            task_image_input(Path(task["path"]), task["image"])
    cases = [{"id": f"{agent}-{task}-r{repeat}", "agent": agent, "task": task, "recording": "on"}
             for repeat in (1, 2) for agent in ("codex", "claude", "hermes") if agent in expected_agents for task in ids]
    cases += [{"id": "paired-" + mode, "agent": pair["agent"], "task": pair["task"], "recording": mode} for mode in pair["order"]]
    return {"declaration_complete": not missing, "missing": missing, "local_inputs_checked": verify_local,
            "real_matrix_trials": matrix_trials, "additional_paired_trials": 2, "cases": cases,
            "excluded_agents": ["claude"] if amended else [],
            "provider_cap_verification_waived": waiver is not None,
            "qualification_passed": False, "paid_launcher_available": False,
            "provider_billing_cap_verified": False,
            "scope": "declaration_and_optional_local_hash_checks_not_spending_authority_or_experiment_results"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--verify-local", action="store_true")
    parser.add_argument("--require-approved", action="store_true")
    args = parser.parse_args()
    try:
        with args.plan.open("rb") as source:
            raw = source.read((1 << 20) + 1)
        require(len(raw) <= 1 << 20, "plan_file_limit_exceeded")
        result = validate(json.loads(raw), args.verify_local or args.require_approved)
        result["plan_file_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, sort_keys=True))
        return 2 if args.require_approved and not result["declaration_complete"] else 0
    except Exception as error:
        print(json.dumps({"qualification_passed": False, "error": str(error) if isinstance(error, PlanFailure) else type(error).__name__}), file=sys.stderr)
        return 1


def bind_case(args, fresh):
    """Bind a declared case before launch; not spending authority or a ledger."""
    path, case_id = getattr(args, "experiment_plan", None), getattr(args, "experiment_case", None)
    if path is None and case_id is None:
        return None
    require(path is not None and bool(case_id) and bool(getattr(args, "task", None)), "experiment_plan_and_case_require_fresh_task")
    identity = file_identity(path)
    require(identity["bytes"] <= 1 << 20, "plan_file_limit_exceeded")
    with path.open("rb") as src:
        raw = src.read((1 << 20) + 1)
    require(hashlib.sha256(raw).hexdigest() == identity["sha256"], "experiment_plan_changed_while_reading")
    plan = json.loads(raw)
    declaration = validate(plan)
    require(declaration["declaration_complete"], "experiment_declaration_incomplete_no_launch")
    cases = [case for case in declaration["cases"] if case["id"] == case_id]
    require(len(cases) == 1, "experiment_case_not_in_plan")
    case = cases[0]
    agent = plan["agents"][case["agent"]]
    task = next(task for task in plan["tasks"] if task["id"] == case["task"])
    require(args.agent == case["agent"] and args.model == agent["model"]
            and args.upstream == agent["upstream"] and args.recording_mode == case["recording"]
            and str(args.task.absolute()) == task["path"] and args.task_image == task["image"]
            and args.agent_timeout == plan["limits"]["agent_timeout_seconds"]
            and args.verifier_timeout == plan["limits"]["verifier_timeout_seconds"]
            and plan["limits"]["setup_timeout_seconds"] == 600, "workflow_arguments_differ_from_experiment_case")
    remote = "/tmp/iorec-hermes-runtime.tar.gz" if args.agent == "hermes" else "/opt/iorec-agent/" + args.agent
    require(fresh["uploads"][remote]["sha256"] == agent["artifact"]["sha256"]
            and fresh["uploads"]["/tmp/iorec-bin"]["sha256"] == plan["recorder"]["sha256"]
            and fresh["task"]["sha256"] == task["source_tree_sha256"]
            and fresh["task_image_override"]["pinned_reference"] == task["image"], "experiment_input_artifacts_differ")
    ledger = getattr(args, "experiment_ledger", None) or path.with_name(path.name + ".ledger")
    return {"case_id": case_id, "plan_path": str(path.absolute()), "plan_sha256": identity["sha256"],
            "ledger_path": str(ledger.absolute()),
            "expected_result": {"agent": {"codex": "codex", "claude": "claude-code", "hermes": "hermes"}[args.agent],
                                "agent_version": agent["version"], "model": agent["model"], "task": task["id"]}}


if __name__ == "__main__":
    sys.exit(main())
