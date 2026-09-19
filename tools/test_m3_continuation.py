"""Model-free tests for explicitly authorized forward-only M3 continuation."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import harbor_audit_workflow as workflow
import m3_experiment_plan as plans
import m3_trial_ledger as ledger
import test_m3_experiment_plan as fixtures


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = fixtures.PlanTests(); fixture.setUp()
        self.previous = fixture.amended_fixture()
        self.previous["budget"]["total_usd"] = "20.00"
        full = plans.validate(self.previous)["cases"]
        previous_plan = self.artifact("previous", self.previous)
        previous_book = self.artifact("previous-ledger", {
            "plan_sha256": previous_plan["sha256"], "cases": [
                {"case_id": c["id"], "status": "ready" if i < 2 else "halted",
                 "receipt": {"reported_cost_usd": "0.25" if i < 2 else None}}
                for i, c in enumerate(full[:3])]})
        self.plan = copy.deepcopy(self.previous)
        self.plan["schema_version"] = 4
        self.plan["budget"]["total_usd"] = "18.50"
        self.plan["limits"].pop("stop_on_unknown_or_exceeded_cost")
        self.plan["limits"].update(stop_on_recording_gap=False, stop_on_unclassified_failure=False,
                                   stop_on_unknown_cost=False, stop_on_exceeded_cost=True)
        self.amendment = {"case_ids": [c["id"] for c in full[3:]],
                          "prior_runs": [{"plan": previous_plan, "ledger": previous_book}],
                          "retained_liability_usd": "1.50", "original_total_usd": "20.00"}
        self.approval = {**self.amendment, "recorder_sha256": self.plan["recorder"]["sha256"],
                         "user_reply": "synthetic approval fixture",
                         "policy": "retain_failed_results_continue_unknown_cost_no_retries"}
        self.amendment["approval"] = self.artifact("approval", self.approval)
        self.plan["authorized_continuation"] = self.amendment
        self.plan_path = Path(self.artifact("continuation", self.plan)["path"])
        self.plan_hash = workflow.digest(self.plan_path)
        self.book_path = self.root / "ledger"

    def artifact(self, name, value):
        path = self.root / (name + ".json")
        workflow.atomic_json(path, value)
        return {"path": str(path), "sha256": workflow.digest(path)}

    def open(self):
        return ledger.Ledger(self.book_path, self.plan_path, self.plan_hash)

    def reserve(self, book, index, suffix=""):
        work = self.root / ("work" + str(index) + suffix); work.mkdir(mode=0o700)
        workflow.atomic_json(work / ".lock", {})
        book.reserve(self.amendment["case_ids"][index], work, "a" * 64)
        book.mark_launch()
        expected = {"agent": "hermes", "model": "openai/test-model"}
        return {"config": {"experiment": {"case_id": book.active["case_id"],
                    "plan_sha256": self.plan_hash, "expected_result": expected}},
                "status": "incomplete", "launch_intent": {"exit_code": 0,
                    "ledger_reservation_id": book.active["reservation_id"]},
                "trial_summary": {"reported_cost_usd": None, "benchmark": {
                    **expected, "status": "completed", "reward": 0, "artifact_sha256": "b" * 64}}}

    def settle(self, book, state):
        path = Path(book.active["work_dir"]) / "report.json"
        workflow.atomic_json(path, {"workflow_status": state["status"], "qualification_passed": state["status"] == "completed"})
        return book.settle(state, workflow.digest(path))

    def test_only_seven_unstarted_cases_full_target_unchanged(self):
        declaration = plans.validate(self.plan)
        plans.verify_continuation(self.plan)
        self.assertEqual(len(declaration["cases"]), 7)
        self.assertEqual(declaration["real_matrix_trials"], 8)
        self.assertEqual(declaration["additional_paired_trials"], 2)
        with self.open() as book:
            with self.assertRaisesRegex(ledger.LedgerFailure, "case_not_in"):
                book.reserve("hermes-cancel-async-tasks-r1", self.root, "a" * 64)

    def test_terminal_failed_observation_and_unknown_cost_allow_next_without_qualifying(self):
        with self.open() as book:
            state = self.reserve(book, 0)
            result = self.settle(book, state)
            self.assertFalse(result["stop_further_paid_trials"])
            self.assertEqual(result["ledger_status"], "observed")
            self.assertTrue(result["unresolved_findings_retained"])
            self.assertEqual(book.liabilities(), 1)
            self.assertIsNone(book.active["receipt"]["reported_cost_usd"])
            self.assertFalse(json.loads((Path(book.active["work_dir"]) / "report.json").read_text())["qualification_passed"])
        with self.open() as book:
            self.reserve(book, 1)
            self.assertEqual(len(book.state["cases"]), 2)

    def test_terminal_benchmark_timeout_can_be_retained_as_failed_result(self):
        with self.open() as book:
            state = self.reserve(book, 0)
            state["trial_summary"]["benchmark"]["status"] = "timeout"
            result = self.settle(book, state)
            self.assertFalse(result["stop_further_paid_trials"])
            self.assertIn("benchmark_not_completed", result["stop_reasons"])

    def test_unknown_cost_does_not_demote_a_successful_capture(self):
        with self.open() as book:
            state = self.reserve(book, 0); state["status"] = "completed"
            control = self.settle(book, state)
            self.assertFalse(control["stop_further_paid_trials"])
            self.assertTrue(control["unresolved_findings_retained"])
            self.assertEqual(book.active["receipt"]["stop_reasons"], ["reported_cost_unknown"])
            report = json.loads((Path(book.active["work_dir"]) / "report.json").read_text())
            self.assertTrue(report["qualification_passed"])

    def test_missing_terminal_evidence_wrong_identity_or_live_child_still_halts(self):
        for variant in ("hash", "exit", "identity", "nonce"):
            with self.subTest(variant=variant):
                self.book_path = self.root / ("ledger-" + variant)
                with self.open() as book:
                    state = self.reserve(book, 0, variant)
                    if variant == "hash": state["trial_summary"]["benchmark"]["artifact_sha256"] = None
                    if variant == "exit": state["launch_intent"].pop("exit_code")
                    if variant == "identity": state["trial_summary"]["benchmark"]["model"] = "other"
                    if variant == "nonce": state["launch_intent"].pop("ledger_reservation_id")
                    self.assertTrue(self.settle(book, state)["stop_further_paid_trials"])

    def test_exceeded_cost_is_not_waived(self):
        with self.open() as book:
            state = self.reserve(book, 0)
            state["trial_summary"]["reported_cost_usd"] = 2
            self.assertTrue(self.settle(book, state)["stop_further_paid_trials"])

    def test_no_automatic_retry_of_observed_case(self):
        with self.open() as book:
            state = self.reserve(book, 0)
            self.settle(book, state)
            with self.assertRaisesRegex(ledger.LedgerFailure, "no_restart"):
                book.reserve(book.active["case_id"], Path(book.active["work_dir"]), "a" * 64)

    def test_changed_failure_report_blocks_continuation(self):
        with self.open() as book:
            state = self.reserve(book, 0)
            self.settle(book, state)
            workflow.atomic_json(Path(book.active["work_dir"]) / "report.json", {"workflow_status": "completed"})
            with self.assertRaisesRegex(ledger.LedgerFailure, "prior_report_changed"):
                self.reserve(book, 1)

    def test_policy_is_explicit_and_existing_strict_plans_remain_strict(self):
        changed = copy.deepcopy(self.plan)
        changed["limits"]["automatic_retries"] = 1
        with self.assertRaises(plans.PlanFailure): plans.validate(changed)
        changed = copy.deepcopy(self.previous)
        changed["limits"]["stop_on_recording_gap"] = False
        with self.assertRaises(plans.PlanFailure): plans.validate(changed)

    def test_no_prior_case_retry_skipped_remaining_case_or_released_liability(self):
        for variant in ("retry", "skip", "budget", "digest"):
            with self.subTest(variant=variant):
                p = copy.deepcopy(self.plan); a = p["authorized_continuation"]
                if variant == "retry": a["case_ids"].insert(0, "hermes-cancel-async-tasks-r1")
                if variant == "skip": a["case_ids"].pop(0)
                if variant == "budget": a["retained_liability_usd"] = "1.00"
                if variant == "digest": a["prior_runs"][0]["ledger"]["sha256"] = "0" * 64
                approval = {**self.approval, **{k: v for k, v in a.items() if k != "approval"}}
                a["approval"] = self.artifact("changed-approval", approval)
                with self.assertRaises(plans.PlanFailure): plans.verify_continuation(p)


if __name__ == "__main__":
    unittest.main()
