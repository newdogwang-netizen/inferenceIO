from __future__ import annotations

import copy
from decimal import Decimal
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import harbor_audit_workflow as workflow
from m3_experiment_plan import validate
import m3_trial_ledger as ledger


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = json.loads((workflow.ROOT / "examples/m3-experiment-plan.json").read_text())
        for name, agent in self.plan["agents"].items():
            agent["model"] = ("anthropic" if name == "claude" else "openai") + "/fixture"
        self.plan["budget"].update(total_usd="14", per_trial_usd="1", approval_reference="synthetic-not-actual-approval",
                                   provider_cap_evidence_sha256="0" * 64)
        self.plan_path = self.root / "plan.json"
        workflow.atomic_json(self.plan_path, self.plan)
        self.plan_hash = workflow.digest(self.plan_path)
        self.cases = validate(self.plan)["cases"]
        self.path = self.root / "ledger"
        self.work = []
        for i in range(14):
            path = self.root / ("work-" + str(i))
            path.mkdir(mode=0o700)
            self.work.append(path)

    def open(self):
        return ledger.Ledger(self.path, self.plan_path, self.plan_hash)

    def reserve(self, book, index=0, intent=None):
        return book.reserve(self.cases[index]["id"], self.work[index], "a" * 64, intent)

    def state(self, book, amount=0.2, benchmark_status="completed", workflow_status="completed"):
        return {"config": {"experiment": {"case_id": book.active["case_id"], "plan_sha256": self.plan_hash}},
                "status": workflow_status, "launch_intent": {"ledger_reservation_id": book.active["reservation_id"]},
                "trial_summary": {"reported_cost_usd": amount,
                    "benchmark": {"status": benchmark_status, "reward": 0, "artifact_sha256": "b" * 64}}}

    def report(self, book, state):
        work = Path(book.active["work_dir"])
        if not (work / ".lock").exists():
            workflow.atomic_json(work / ".lock", {})
        workflow.atomic_json(work / "report.json", {"workflow_status": state["status"], "fixture_only": True})
        return workflow.digest(work / "report.json")

    def test_serial_reservation_and_exact_decimal_accounting_all_fourteen_cases(self):
        with self.open() as book:
            for i, case in enumerate(self.cases):
                result = self.reserve(book, i)
                self.assertFalse(result["resumed"])
                self.assertEqual(book.liabilities(), Decimal("0.1") * i + 1)
                book.mark_launch()
                final = "baseline_completed" if case["recording"] == "off" else "completed"
                state = self.state(book, 0.1, workflow_status=final)
                control = book.settle(state, self.report(book, state))
                self.assertFalse(control["stop_further_paid_trials"])
                self.assertEqual(book.liabilities(), Decimal("0.1") * (i + 1))
            self.assertEqual(len(book.state["cases"]), 14)
        with self.open() as again:
            self.assertEqual(again.liabilities(), Decimal("1.4"))
        self.assertEqual((self.path / "ledger.json").stat().st_mode & 0o777, 0o600)

    def test_unknown_cost_halts_next_case_and_is_not_zero(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            control = book.settle(self.state(book, None), "c" * 64)
            self.assertTrue(control["stop_further_paid_trials"])
            self.assertIn("reported_cost_unknown", control["stop_reasons"])
            self.assertIsNone(book.active["receipt"]["reported_cost_usd"])
            self.assertEqual(book.liabilities(), Decimal(1))
            with self.assertRaisesRegex(ledger.LedgerFailure, "not_settled"):
                self.reserve(book, 1)

    def test_excess_cost_halts_and_cannot_disappear_on_revalidation(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            state = self.state(book, 20)
            control = book.settle(state, "c" * 64)
            self.assertIn("declared_total_budget_exceeded", control["stop_reasons"])
            self.assertEqual(book.liabilities(), Decimal(20))
            self.reserve(book, intent=state["launch_intent"])
            self.assertEqual(book.liabilities(), Decimal(20))
            control = book.settle(self.state(book, 0.1), "c" * 64)
            self.assertIn("prior_reported_cost_exceeds_per_trial_limit", control["stop_reasons"])
            self.assertEqual(book.liabilities(), Decimal(20))

    def test_incomplete_workflow_and_benchmark_error_stop_but_reward_zero_does_not(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            state = self.state(book, benchmark_status="error", workflow_status="incomplete")
            result = book.settle(state, "c" * 64)
            self.assertIn("workflow_incomplete_or_failed", result["stop_reasons"])
            self.assertIn("benchmark_not_completed", result["stop_reasons"])
            self.reserve(book, intent=state["launch_intent"])
            self.assertFalse(book.settle(self.state(book), "c" * 64)["stop_further_paid_trials"])

    def test_resume_requires_same_workspace_inputs_and_durable_launch_nonce(self):
        with self.open() as book:
            self.reserve(book)
            self.assertTrue(self.reserve(book)["resumed"])
            nonce = book.mark_launch()
            with self.assertRaisesRegex(ledger.LedgerFailure, "missing_workflow_intent"):
                self.reserve(book)
            with self.assertRaisesRegex(ledger.LedgerFailure, "already_marked"):
                book.mark_launch()
            with self.assertRaisesRegex(ledger.LedgerFailure, "different_inputs_or_workspace"):
                book.reserve(self.cases[0]["id"], self.work[1], "a" * 64, {"ledger_reservation_id": nonce})
            with self.assertRaisesRegex(ledger.LedgerFailure, "different_inputs_or_workspace"):
                book.reserve(self.cases[0]["id"], self.work[0], "b" * 64, {"ledger_reservation_id": nonce})
            self.assertTrue(self.reserve(book, intent={"ledger_reservation_id": nonce})["resumed"])

    def test_preexisting_launch_cannot_be_retroactively_admitted_or_sequence_skipped(self):
        with self.open() as book:
            with self.assertRaisesRegex(ledger.LedgerFailure, "not_next"):
                self.reserve(book, 1)
            with self.assertRaisesRegex(ledger.LedgerFailure, "not_admitted"):
                self.reserve(book, intent={"pid": 12345})
            self.assertEqual(book.state["cases"], [])

    def test_same_case_revalidation_invalidates_previous_ready_receipt_until_settled(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            state = self.state(book)
            book.settle(state, "c" * 64)
            self.reserve(book, intent=state["launch_intent"])
            self.assertEqual(book.active["status"], "reserved")
            self.assertEqual(len(book.active["history"]), 1)
            with self.assertRaisesRegex(ledger.LedgerFailure, "not_settled"):
                self.reserve(book, 1)
        with self.open() as again:
            with self.assertRaisesRegex(ledger.LedgerFailure, "not_settled"):
                self.reserve(again, 1)

    def test_changed_or_missing_prior_report_blocks_next_case(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            state = self.state(book)
            book.settle(state, self.report(book, state))
        path = self.work[0] / "report.json"
        workflow.atomic_json(path, {"workflow_status": "incomplete"})
        with self.open() as book:
            with self.assertRaisesRegex(ledger.LedgerFailure, "prior_report_changed"):
                self.reserve(book, 1)
            self.assertEqual(len(book.state["cases"]), 1)
            self.assertIsNone(book.active)
        path.unlink()
        with self.open() as book:
            with self.assertRaisesRegex(ledger.LedgerFailure, "prior_report_unavailable"):
                self.reserve(book, 1)

    def test_busy_prior_workspace_blocks_admission_and_admission_fences_revalidation(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            state = self.state(book)
            book.settle(state, self.report(book, state))
        with (self.work[0] / ".lock").open("r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.open() as book:
                with self.assertRaisesRegex(ledger.LedgerFailure, "prior_workflow_busy"):
                    self.reserve(book, 1)
                self.assertIsNone(book.active)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            with self.open() as book:
                self.reserve(book, 1)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_child_inherits_lock_after_parent_closes_and_pending_reservation_remains(self):
        with self.open() as book:
            self.reserve(book)
            book.mark_launch()
            child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"],
                                     stdin=subprocess.PIPE, pass_fds=(book.lock.fileno(),))
        try:
            with self.assertRaisesRegex(ledger.LedgerFailure, "child_holds_ledger"):
                with self.open():
                    pass
        finally:
            child.communicate(timeout=5)
        with self.open() as book:
            with self.assertRaisesRegex(ledger.LedgerFailure, "not_settled"):
                self.reserve(book, 1)

    def test_corruption_plan_change_and_directory_overlap_rejected(self):
        with self.open() as book:
            with self.assertRaisesRegex(ledger.LedgerFailure, "overlap"):
                book.reserve(self.cases[0]["id"], self.path, "a" * 64)
            self.reserve(book)
        raw = json.loads((self.path / "ledger.json").read_text())
        raw["cases"][0]["status"] = "ready"
        workflow.atomic_json(self.path / "ledger.json", raw)
        with self.assertRaises(ledger.LedgerFailure):
            with self.open():
                pass
        self.plan["budget"]["total_usd"] = "15"
        workflow.atomic_json(self.plan_path, self.plan)
        with self.assertRaisesRegex(ledger.LedgerFailure, "bound_complete_plan"):
            self.open()

    def test_invalid_costs_and_unsafe_staging_do_not_overwrite_unrelated_data(self):
        for value in (True, -1, "NaN", "Infinity", "-0.1"):
            with self.subTest(value=value), self.assertRaises(ledger.LedgerFailure):
                ledger.cost(value)
        with self.open():
            pass
        victim = self.root / "unrelated"
        victim.write_text("preserve")
        victim.chmod(0o600)
        os.link(victim, self.path / "ledger.json.next")
        with self.assertRaisesRegex(ledger.LedgerFailure, "unsafe_ledger_staging"):
            with self.open():
                pass
        self.assertEqual(victim.read_text(), "preserve")

    def workflow_args(self, index=0):
        return workflow.parser().parse_args(["--work-dir", str(self.work[index]), "--task", str(self.root / "task"),
            "--key-file", str(self.root / "key"), "--experiment-plan", str(self.plan_path),
            "--experiment-case", self.cases[index]["id"], "--experiment-ledger", str(self.path)])

    def fixture_preflight(self, w, index):
        w.state["config"] = {"experiment": {"case_id": self.cases[index]["id"], "plan_sha256": self.plan_hash,
            "ledger_path": str(self.path), "expected_result": {}}}
        return {"fixture_only": True}

    def fixture_record(self, w, amount):
        nonce = w.ledger.mark_launch()
        w.state["launch_intent"] = {"ledger_reservation_id": nonce}
        w.state["trial_summary"] = {"reported_cost_usd": amount, "benchmark": {
            "status": "completed", "reward": 0, "artifact_sha256": "b" * 64}}
        return {"fixture_only": True}

    def test_workflow_unknown_cost_blocks_next_record_stage_and_receipt_binds_report(self):
        args = self.workflow_args()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=lambda: self.fixture_preflight(w, 0)), \
                 mock.patch.object(w, "record", side_effect=lambda: self.fixture_record(w, None)), \
                 mock.patch.object(w, "integrity", return_value={}), mock.patch.object(w, "audit", return_value={}), \
                 mock.patch.object(w, "import_run", return_value={}), mock.patch.object(w, "qualify_platform", return_value={}):
                w.run()
            self.assertTrue(w.experiment_control["stop_further_paid_trials"])
            self.assertIsNone(w.ledger)
        stored, _ = ledger.read_json(self.path / "ledger.json")
        self.assertEqual(stored["cases"][0]["receipt"]["report_sha256"], workflow.digest(work.path / "report.json"))
        args = self.workflow_args(1)
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=lambda: self.fixture_preflight(w, 1)), \
                 mock.patch.object(w, "record") as record:
                with self.assertRaisesRegex(ledger.LedgerFailure, "not_settled"):
                    w.run()
                record.assert_not_called()
            self.assertNotIn("launch_intent", w.state)
            self.assertIsNone(w.ledger)

    def test_preflight_only_does_not_reserve_allowance_or_create_ledger(self):
        args = self.workflow_args()
        args.preflight_only = True
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=lambda: self.fixture_preflight(w, 0)):
                w.run()
        self.assertFalse(self.path.exists())
        self.assertIsNone(w.experiment_control)

    def test_failed_revalidation_before_admission_cannot_leave_a_usable_ready_receipt(self):
        args = self.workflow_args()
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=lambda: self.fixture_preflight(w, 0)), \
                 mock.patch.object(w, "record", side_effect=lambda: self.fixture_record(w, 0.1)), \
                 mock.patch.object(w, "integrity", return_value={}), mock.patch.object(w, "audit", return_value={}), \
                 mock.patch.object(w, "import_run", return_value={}), mock.patch.object(w, "qualify_platform", return_value={}):
                w.run()
            self.assertFalse(w.experiment_control["stop_further_paid_trials"])
            with mock.patch.object(w, "preflight", side_effect=workflow.Failure("changed_input_fixture")):
                with self.assertRaisesRegex(workflow.Failure, "changed_input_fixture"):
                    w.run()
        args = self.workflow_args(1)
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            with mock.patch.object(w, "preflight", side_effect=lambda: self.fixture_preflight(w, 1)), \
                 mock.patch.object(w, "record") as record:
                with self.assertRaisesRegex(ledger.LedgerFailure, "prior_report_changed"):
                    w.run()
                record.assert_not_called()
                self.assertNotIn("launch_intent", w.state)

    def test_actual_record_launch_receives_both_locks_and_durable_nonce_before_popen(self):
        args = self.workflow_args()
        args.model, args.upstream = "openai/fixture", "https://api.openai.com/v1"
        with workflow.Workspace(args.work_dir) as work:
            w = workflow.Workflow(args, work)
            self.fixture_preflight(w, 0)
            w.state["config"]["fresh_inputs"] = {"harbor": {"launcher": {"path": "/fixture/harbor"}}}
            w.admit_experiment()
            try:
                def fake_launch(*_, **kwargs):
                    self.assertEqual(kwargs["pass_fds"], (work.lock.fileno(), w.ledger.lock.fileno()))
                    state = workflow.read_json(work.path / "state.json")
                    book, _ = ledger.read_json(self.path / "ledger.json")
                    self.assertTrue(book["cases"][0]["launch_started"])
                    self.assertEqual(state["launch_intent"]["ledger_reservation_id"], book["cases"][0]["reservation_id"])
                    job = work.path / "jobs/audit/fixture-trial"
                    job.mkdir(parents=True)
                    workflow.atomic_json(job / "result.json", {})
                    return mock.Mock(pid=12345, wait=mock.Mock(return_value=0))
                with mock.patch.object(w, "assert_fresh_inputs"), mock.patch.object(workflow.subprocess, "Popen", side_effect=fake_launch) as launch, \
                        mock.patch.object(workflow, "benchmark_from_trial", side_effect=workflow.Failure("fixture_stop_after_launch_checks")):
                    with self.assertRaisesRegex(workflow.Failure, "fixture_stop_after"):
                        w.record()
                    self.assertEqual(launch.call_count, 1)
            finally:
                w.ledger.__exit__()
                w.ledger = None


if __name__ == "__main__":
    unittest.main()
