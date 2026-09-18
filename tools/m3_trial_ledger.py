"""Private, serial M3 admission ledger for one explicitly shared directory.

This is not user approval, a provider billing cap, or a machine-wide intercept.
Only callers using the same ledger coordinate. Unknown outcomes reserve their
full declared allowance and block later cases; same-case evidence recovery is
allowed, never an automatic replacement model run.
"""
from __future__ import annotations

import datetime as dt
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from m3_experiment_plan import validate


class LedgerFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise LedgerFailure(code)


def private(path, directory=False):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.getuid() and not info.st_mode & 0o077, "ledger_path_must_be_private_and_regular")


def read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as src:
        require(stat.S_ISREG(os.fstat(src.fileno()).st_mode), "ledger_input_not_regular")
        raw = src.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20, "ledger_input_too_large")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def atomic_json(path, value):
    temp = path.with_name(path.name + ".next")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "w") as out:
        info = os.fstat(out.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and not info.st_mode & 0o077, "unsafe_ledger_staging_file")
        out.truncate(0)
        json.dump(value, out, sort_keys=True, allow_nan=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def cost(value):
    if value is None:
        return None
    require(type(value) in (str, int, float), "invalid_ledger_cost")
    parsed = Decimal(str(value))
    require(parsed.is_finite() and parsed >= 0, "invalid_ledger_cost")
    return parsed


class Ledger:
    def __init__(self, path: Path, plan_path: Path, plan_sha256: str):
        self.path = path.absolute()
        self.plan, actual = read_json(plan_path)
        declaration = validate(self.plan)
        require(declaration["declaration_complete"] and actual == plan_sha256, "ledger_requires_bound_complete_plan")
        self.plan_sha256 = actual
        self.cases = declaration["cases"]
        self.ids = [case["id"] for case in self.cases]
        self.per_trial = Decimal(self.plan["budget"]["per_trial_usd"])
        self.total = Decimal(self.plan["budget"]["total_usd"])
        self.lock = None
        self.receipt_locks = {}
        self.state = None
        self.active = None

    def __enter__(self):
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        private(self.path, directory=True)
        fd = os.open(self.path / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "r+")
        try:
            private(self.path / ".lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LedgerFailure("another_experiment_or_child_holds_ledger_no_launch") from None
            state_path = self.path / "ledger.json"
            if state_path.exists() or state_path.is_symlink():
                private(state_path)
                self.state, _ = read_json(state_path)
            else:
                require(all(p.name in (".lock", "ledger.json.next") for p in self.path.iterdir()), "ledger_directory_not_empty_or_initialized")
                self.state = {"schema_version": 1, "plan_sha256": self.plan_sha256, "cases": []}
            self.check()
            self.save()
            return self
        except BaseException:
            self.lock.close()
            self.lock = None
            raise

    def __exit__(self, *_):
        for fd in self.receipt_locks.values():
            os.close(fd)
        self.receipt_locks.clear()
        self.lock.close()

    def check(self):
        require(isinstance(self.state, dict) and set(self.state) == {"schema_version", "plan_sha256", "cases"}
                and type(self.state["schema_version"]) is int and self.state["schema_version"] == 1
                and self.state["plan_sha256"] == self.plan_sha256, "ledger_plan_or_schema_changed")
        entries = self.state["cases"]
        require(isinstance(entries, list) and len(entries) <= len(self.ids), "invalid_ledger_cases")
        for index, entry in enumerate(entries):
            require(isinstance(entry, dict) and set(entry) == {"case_id", "work_dir", "inputs_sha256", "reserved_usd", "reserved_at", "status", "receipt", "reservation_id", "launch_started", "history"}, "invalid_ledger_entry")
            require(entry["case_id"] == self.ids[index] and entry["reserved_usd"] == str(self.per_trial)
                    and entry["status"] in ("reserved", "ready", "halted")
                    and isinstance(entry["work_dir"], str) and Path(entry["work_dir"]).is_absolute()
                    and isinstance(entry["inputs_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["inputs_sha256"])
                    and isinstance(entry["reservation_id"], str) and re.fullmatch(r"[0-9a-f]{32}", entry["reservation_id"])
                    and type(entry["launch_started"]) is bool and isinstance(entry["history"], list)
                    and len(entry["history"]) <= 32, "invalid_ledger_entry")
            receipt = entry["receipt"]
            require((entry["status"] == "reserved" and receipt is None)
                    or (entry["status"] != "reserved" and isinstance(receipt, dict)), "invalid_ledger_receipt")
            for r in entry["history"] + ([receipt] if receipt is not None else []):
                require(isinstance(r, dict) and set(r) == {"at", "workflow_status", "report_sha256", "trial_result_sha256", "reported_cost_usd", "stop_reasons", "billing_verified"}
                        and r["billing_verified"] is False and isinstance(r["stop_reasons"], list)
                        and all(reason in {"missing_ledger_launch_link", "workflow_incomplete_or_failed", "benchmark_not_completed", "reported_cost_unknown", "reported_cost_exceeds_per_trial_limit", "declared_total_budget_exceeded", "prior_reported_cost_exceeds_per_trial_limit"} for reason in r["stop_reasons"]), "invalid_ledger_receipt")
                cost(r["reported_cost_usd"])
            if entry["status"] == "ready":
                amount = cost(receipt["reported_cost_usd"])
                require(not receipt["stop_reasons"] and amount is not None and amount <= self.per_trial
                            and entry["launch_started"]
                            and all(cost(r["reported_cost_usd"]) <= self.per_trial for r in entry["history"] if r["reported_cost_usd"] is not None)
                            and receipt["workflow_status"] in ("completed", "baseline_completed"), "invalid_ready_ledger_entry")
            if entry["status"] == "halted":
                require(bool(receipt["stop_reasons"]), "halted_ledger_requires_stop_reason")

    def save(self):
        self.check()
        atomic_json(self.path / "ledger.json", self.state)

    def liabilities(self):
        total = Decimal(0)
        for entry in self.state["cases"]:
            receipts = entry["history"] + ([entry["receipt"]] if entry["receipt"] else [])
            amounts = [cost(r["reported_cost_usd"]) for r in receipts if r["reported_cost_usd"] is not None]
            actual = max(amounts) if amounts else None
            total += actual if entry["status"] == "ready" else max(self.per_trial, actual or Decimal(0))
        return total

    def check_ready_reports(self):
        # Preflight may invalidate a prior workflow report before it can acquire
        # this ledger. Never admit a new launch from the old receipt alone.
        # Nonblocking shared workspace locks also fence concurrent revalidation
        # between this check and the new launch, without lock-order deadlocks.
        for entry in self.state["cases"]:
            work = Path(entry["work_dir"])
            private(work, directory=True)
            if work not in self.receipt_locks:
                lock_path = work / ".lock"
                private(lock_path)
                fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    require(stat.S_ISREG(os.fstat(fd).st_mode), "prior_workspace_lock_not_regular")
                    try:
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise LedgerFailure("prior_workflow_busy_no_next_launch") from None
                    self.receipt_locks[work] = fd
                except BaseException:
                    os.close(fd)
                    raise
            report_path = work / "report.json"
            try:
                private(report_path)
                report, actual = read_json(report_path)
            except (OSError, ValueError, LedgerFailure):
                raise LedgerFailure("prior_report_unavailable_no_next_launch") from None
            require(actual == entry["receipt"]["report_sha256"]
                    and report.get("workflow_status") == entry["receipt"]["workflow_status"],
                    "prior_report_changed_no_next_launch")

    def reserve(self, case_id: str, work_dir: Path, inputs_sha256: str, launch_intent=None):
        require(case_id in self.ids, "case_not_in_ledger_plan")
        work = work_dir.absolute()
        private(work, directory=True)
        require(not work.resolve().is_relative_to(self.path.resolve()) and not self.path.resolve().is_relative_to(work.resolve()), "ledger_and_workflow_directories_must_not_overlap")
        entries = self.state["cases"]
        existing = next((entry for entry in entries if entry["case_id"] == case_id), None)
        if existing:
            require(existing["work_dir"] == str(work) and existing["inputs_sha256"] == inputs_sha256, "case_already_reserved_for_different_inputs_or_workspace")
            if existing["launch_started"]:
                require((launch_intent or {}).get("ledger_reservation_id") == existing["reservation_id"], "prior_ledger_launch_missing_workflow_intent_no_restart")
            else:
                require(not launch_intent, "workflow_intent_without_ledger_marker")
            # Recovery of the same evidence is allowed; Workflow's durable launch
            # intent independently prohibits an uncertain paid resubmission.
            if existing["receipt"]:
                require(len(existing["history"]) < 32, "ledger_receipt_history_limit_reached")
                existing["history"].append(existing["receipt"])
                existing["receipt"] = None
            existing["status"] = "reserved"
            self.active = existing
            self.save()
            return {"resumed": True, "reserved_usd": existing["reserved_usd"], "reservation_id": existing["reservation_id"]}
        require(all(entry["status"] == "ready" for entry in entries), "prior_case_not_settled_no_next_launch")
        require(not launch_intent, "existing_workflow_launch_not_admitted_by_ledger")
        require(len(entries) < len(self.ids) and self.ids[len(entries)] == case_id, "case_not_next_in_declared_sequence")
        require(self.liabilities() + self.per_trial <= self.total, "declared_total_budget_exhausted")
        require(all(entry["work_dir"] != str(work) for entry in entries), "workflow_directory_already_used_by_another_case")
        self.check_ready_reports()
        self.active = {"case_id": case_id, "work_dir": str(work), "inputs_sha256": inputs_sha256,
                       "reserved_usd": str(self.per_trial), "reserved_at": now(), "status": "reserved", "receipt": None,
                       "reservation_id": uuid.uuid4().hex, "launch_started": False, "history": []}
        entries.append(self.active)
        self.save()
        return {"resumed": False, "reserved_usd": str(self.per_trial), "reservation_id": self.active["reservation_id"]}

    def mark_launch(self):
        require(self.active is not None and not self.active["launch_started"], "ledger_launch_already_marked_no_restart")
        self.active["launch_started"] = True
        self.save()
        return self.active["reservation_id"]

    def settle(self, state, report_sha256):
        require(self.active is not None, "no_active_ledger_case")
        binding = state.get("config", {}).get("experiment", {})
        require(binding.get("case_id") == self.active["case_id"] and binding.get("plan_sha256") == self.plan_sha256,
                "settlement_case_binding_changed")
        mode = next(case["recording"] for case in self.cases if case["id"] == self.active["case_id"])
        final = "completed" if mode == "on" else "baseline_completed"
        summary = state.get("trial_summary") or {}
        benchmark = summary.get("benchmark") or {}
        amount = cost(summary.get("reported_cost_usd"))
        reasons = []
        if not self.active["launch_started"] or (state.get("launch_intent") or {}).get("ledger_reservation_id") != self.active["reservation_id"]:
            reasons.append("missing_ledger_launch_link")
        if state.get("status") != final:
            reasons.append("workflow_incomplete_or_failed")
        if benchmark.get("status") != "completed":
            reasons.append("benchmark_not_completed")
        if amount is None:
            reasons.append("reported_cost_unknown")
        elif amount > self.per_trial:
            reasons.append("reported_cost_exceeds_per_trial_limit")
        if any(cost(r["reported_cost_usd"]) > self.per_trial for r in self.active["history"] if r["reported_cost_usd"] is not None):
            reasons.append("prior_reported_cost_exceeds_per_trial_limit")
        self.active["receipt"] = {"at": now(), "workflow_status": state.get("status"),
            "report_sha256": report_sha256, "trial_result_sha256": benchmark.get("artifact_sha256"),
            "reported_cost_usd": str(amount) if amount is not None else None,
            "stop_reasons": reasons, "billing_verified": False}
        self.active["status"] = "halted" if reasons else "ready"
        if self.liabilities() > self.total:
            self.active["status"] = "halted"
            reasons.append("declared_total_budget_exceeded")
        self.save()
        return {"case_id": self.active["case_id"], "ledger_status": self.active["status"],
                "stop_further_paid_trials": bool(reasons), "stop_reasons": reasons,
                "accounted_liability_usd": str(self.liabilities()), "billing_verified": False}
