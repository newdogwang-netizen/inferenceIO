import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import m3_experiment_plan as plans
import harbor_audit_workflow as workflow


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((Path(__file__).resolve().parents[1] / "examples/m3-experiment-plan.json").read_text())

    def approved_fixture(self):
        result = copy.deepcopy(self.plan)
        for name, agent in result["agents"].items():
            agent["model"] = ("anthropic" if name == "claude" else "openai") + "/test-model"
        result["budget"].update(total_usd="14.00", per_trial_usd="1.00",
            approval_reference="test-fixture-not-actual-user-approval", provider_cap_evidence_sha256="0" * 64)
        return result

    def test_repository_plan_remains_unapproved_and_full_scope(self):
        result = plans.validate(self.plan)
        self.assertFalse(result["declaration_complete"])
        self.assertEqual(len(result["missing"]), 7)
        self.assertEqual(result["real_matrix_trials"], 12)
        self.assertEqual(result["additional_paired_trials"], 2)
        self.assertEqual(len({c["id"] for c in result["cases"]}), 14)
        self.assertFalse(result["qualification_passed"])
        self.assertFalse(result["paid_launcher_available"])

    def test_approval_declaration_is_not_provider_cap_attestation(self):
        result = plans.validate(self.approved_fixture())
        self.assertTrue(result["declaration_complete"])
        self.assertFalse(result["provider_billing_cap_verified"])
        self.assertFalse(result["qualification_passed"])

    def amended_fixture(self):
        p = self.approved_fixture()
        p["schema_version"] = 2
        del p["agents"]["claude"]
        p["scope_amendment"] = {"excluded_agents": ["claude"], "approval_reference": "test-user-exclusion"}
        p["budget"].update(total_usd="10.00", provider_cap_evidence_sha256=None,
            provider_cap_waiver={"approval_reference": "test-user-waiver", "reason": "management API unavailable"})
        return p

    def test_explicit_amendment_has_eight_cases_plus_pair_not_full_scope_or_cap_proof(self):
        result = plans.validate(self.amended_fixture())
        self.assertTrue(result["declaration_complete"])
        self.assertEqual(result["real_matrix_trials"], 8)
        self.assertEqual(result["excluded_agents"], ["claude"])
        self.assertEqual(len(result["cases"]), 10)
        self.assertEqual({c["agent"] for c in result["cases"]}, {"codex", "hermes"})
        self.assertTrue(result["provider_cap_verification_waived"])
        self.assertFalse(result["provider_billing_cap_verified"])
        self.assertFalse(result["qualification_passed"])

    def test_amendment_needs_explicit_scope_and_waiver_approval(self):
        for field in ("scope_amendment", "provider_cap_waiver"):
            p = self.amended_fixture()
            (p if field == "scope_amendment" else p["budget"])[field]["approval_reference"] = " "
            with self.assertRaises(plans.PlanFailure):
                plans.validate(p)
        p = self.amended_fixture()
        p["budget"]["provider_cap_waiver"] = None
        self.assertEqual(plans.validate(p)["missing"], ["budget:provider_cap_evidence_sha256"])
        p = self.amended_fixture()
        p["budget"]["provider_cap_evidence_sha256"] = "0" * 64
        with self.assertRaisesRegex(plans.PlanFailure, "waiver_is_not_provider_cap_evidence"):
            plans.validate(p)
        for excluded in ([], ["hermes"], ["claude", "hermes"]):
            p = self.amended_fixture(); p["scope_amendment"]["excluded_agents"] = excluded
            with self.assertRaises(plans.PlanFailure):
                plans.validate(p)

    def test_amendment_preserves_limits_and_requires_all_ten_reservations(self):
        p = self.amended_fixture(); p["budget"]["total_usd"] = "9.999999"
        with self.assertRaisesRegex(plans.PlanFailure, "eight_trials_plus_two"):
            plans.validate(p)
        for name, value in (("automatic_retries", 1), ("stop_on_unknown_or_exceeded_cost", False)):
            p = self.amended_fixture(); p["limits"][name] = value
            with self.assertRaises(plans.PlanFailure):
                plans.validate(p)
        p = self.amended_fixture(); del p["agents"]["hermes"]
        with self.assertRaises(plans.PlanFailure):
            plans.validate(p)

    def test_budget_includes_both_extra_paired_runs(self):
        p = self.approved_fixture()
        p["budget"]["total_usd"] = "13.999999"
        with self.assertRaisesRegex(plans.PlanFailure, "twelve_trials_plus_two"):
            plans.validate(p)
        p["budget"]["total_usd"] = "14.000000"
        self.assertTrue(plans.validate(p)["declaration_complete"])

    def test_money_does_not_accept_boolean_float_negative_nan_or_infinity(self):
        for value in (True, 1.0, "-1", "NaN", "Infinity", "1e3", "0", "0.000000", "1.0000001"):
            with self.subTest(value=value), self.assertRaises(plans.PlanFailure):
                plans.money(value)

    def test_scope_and_stop_policy_cannot_be_reduced(self):
        variants = []
        p = copy.deepcopy(self.plan); p["repetitions"] = 1; variants.append(p)
        p = copy.deepcopy(self.plan); p["tasks"] = p["tasks"][:1]; variants.append(p)
        p = copy.deepcopy(self.plan); p["tasks"][1]["category"] = p["tasks"][0]["category"]; variants.append(p)
        p = copy.deepcopy(self.plan); del p["agents"]["hermes"]; variants.append(p)
        p = copy.deepcopy(self.plan); p["paired"]["order"] = ["on", "on"]; variants.append(p)
        p = copy.deepcopy(self.plan); p["limits"]["automatic_retries"] = 1; variants.append(p)
        p = copy.deepcopy(self.plan); p["limits"]["stop_on_unknown_or_exceeded_cost"] = False; variants.append(p)
        p = copy.deepcopy(self.plan); p["api_key"] = "must-never-be-in-plan"; variants.append(p)
        p = self.approved_fixture(); p["budget"]["approval_reference"] = " "; variants.append(p)
        for p in variants:
            with self.assertRaises(plans.PlanFailure):
                plans.validate(p)

    def test_wrong_provider_and_placeholder_models_rejected(self):
        for model in ("anthropic/test-model", "openai/preflight-placeholder", "openai/", "openai/YOUR_MODEL"):
            p = self.approved_fixture()
            p["agents"]["codex"]["model"] = model
            with self.subTest(model=model), self.assertRaises(plans.PlanFailure):
                plans.validate(p)

    def test_local_validation_checks_all_four_runtime_inputs_and_two_tasks(self):
        artifacts = [self.plan["recorder"], *[a["artifact"] for a in self.plan["agents"].values()]]
        hashes = {a["path"]: a["sha256"] for a in artifacts}
        trees = {t["path"]: t["source_tree_sha256"] for t in self.plan["tasks"]}
        with mock.patch.object(plans, "file_identity", side_effect=lambda p: {"sha256": hashes[str(p)]}) as files, \
             mock.patch.object(plans, "tree_identity", side_effect=lambda p, **_: {"sha256": trees[str(p)]}) as tree, \
             mock.patch.object(plans, "task_image_input", return_value={}) as images:
            result = plans.validate(self.plan, verify_local=True)
            self.assertTrue(result["local_inputs_checked"])
            self.assertEqual(files.call_count, 4)
            self.assertEqual(tree.call_count, 2)
            self.assertEqual(images.call_count, 2)
            hashes[self.plan["recorder"]["path"]] = "0" * 64
            with self.assertRaisesRegex(plans.PlanFailure, "runtime_digest_changed"):
                plans.validate(self.plan, verify_local=True)


class RecoveryPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = PlanTests(); fixture.setUp()
        self.previous = fixture.amended_fixture()
        self.previous["budget"]["total_usd"] = "20.00"
        self.case = "hermes-cancel-async-tasks-r1"
        self.report = self.artifact("report", {"workflow_status": "incomplete", "qualification_passed": False})
        self.prior_plan = self.artifact("plan", self.previous)
        self.book = {"plan_sha256": self.prior_plan["sha256"], "cases": [
            {"case_id": "codex-cancel-async-tasks-r1", "status": "ready", "receipt": {"reported_cost_usd": "0.5"}},
            {"case_id": self.case, "status": "halted", "receipt": {
                "reported_cost_usd": None, "report_sha256": self.report["sha256"]}}]}
        self.prior_ledger = self.artifact("ledger", self.book)
        self.approval = {"case_id": self.case, "allowed_replacements": 1, "user_reply": "synthetic approval fixture",
                         "prior_ledger_sha256": self.prior_ledger["sha256"], "retained_liability_usd": "1.50",
                         "original_total_usd": "20.00", "recorder_sha256": self.previous["recorder"]["sha256"]}
        self.plan = copy.deepcopy(self.previous)
        self.plan["schema_version"] = 3
        self.plan["budget"]["total_usd"] = "18.50"
        self.plan["authorized_recovery"] = {"case_id": self.case, "prior_plan": self.prior_plan,
            "prior_ledger": self.prior_ledger, "prior_report": self.report,
            "approval": self.artifact("approval", self.approval),
            "retained_liability_usd": "1.50", "original_total_usd": "20.00"}

    def artifact(self, name, value):
        path = self.root / (name + ".json")
        workflow.atomic_json(path, value)
        return {"path": str(path), "sha256": workflow.digest(path)}

    def test_single_replacement_does_not_reduce_matrix_or_admit_other_cases(self):
        result = plans.validate(self.plan)
        plans.verify_recovery(self.plan)
        self.assertEqual(result["real_matrix_trials"], 8)
        self.assertEqual(result["additional_paired_trials"], 2)
        self.assertEqual([x["id"] for x in result["cases"]], [self.case])
        self.assertTrue(result["single_case_recovery"])
        import m3_trial_ledger
        plan_path = Path(self.artifact("recovery", self.plan)["path"])
        work = self.root / "work"; work.mkdir(mode=0o700)
        with m3_trial_ledger.Ledger(self.root / "new-ledger", plan_path, workflow.digest(plan_path)) as book:
            book.reserve(self.case, work, "a" * 64)
            book.mark_launch()
            with self.assertRaisesRegex(m3_trial_ledger.LedgerFailure, "case_not_in_ledger_plan"):
                book.reserve("hermes-multi-source-data-merger-r1", work, "a" * 64)
            with self.assertRaisesRegex(m3_trial_ledger.LedgerFailure, "no_restart"):
                book.reserve(self.case, work, "a" * 64)

    def test_recovery_cannot_change_model_case_recorder_approval_or_retry_count(self):
        for field, value in (("case_id", "other"), ("allowed_replacements", 2),
                             ("allowed_replacements", True), ("recorder_sha256", "0" * 64)):
            p = copy.deepcopy(self.plan); approval = {**self.approval, field: value}
            p["authorized_recovery"]["approval"] = self.artifact("changed-approval", approval)
            with self.assertRaisesRegex(plans.PlanFailure, "approval_not_bound"):
                plans.verify_recovery(p)
        p = copy.deepcopy(self.plan); p["agents"]["hermes"]["model"] = "openai/other"
        with self.assertRaisesRegex(plans.PlanFailure, "identity_changed"):
            plans.verify_recovery(p)
        p = copy.deepcopy(self.plan); p["authorized_recovery"]["case_id"] = "not-in-plan"
        with self.assertRaisesRegex(plans.PlanFailure, "recovery_case_required"):
            plans.validate(p)

    def test_recovery_preserves_prior_failure_hash_and_reservations(self):
        p = copy.deepcopy(self.plan)
        p["authorized_recovery"]["prior_report"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(plans.PlanFailure, "digest_changed"):
            plans.verify_recovery(p)
        p = copy.deepcopy(self.plan); p["budget"]["total_usd"] = "19.00"
        p["authorized_recovery"]["retained_liability_usd"] = "1.00"
        p["authorized_recovery"]["approval"] = self.artifact("changed-approval", {**self.approval, "retained_liability_usd": "1.00"})
        plans.validate(p)
        with self.assertRaisesRegex(plans.PlanFailure, "cannot_release_prior"):
            plans.verify_recovery(p)
        self.book["cases"][-1]["status"] = "ready"
        p = copy.deepcopy(self.plan)
        p["authorized_recovery"]["prior_ledger"] = self.artifact("changed-ledger", self.book)
        with self.assertRaisesRegex(plans.PlanFailure, "preserved_failed_case"):
            plans.verify_recovery(p)


class CaseBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = PlanTests()
        fixture.setUp()
        self.plan = fixture.approved_fixture()
        self.plan_path = self.root / "plan.json"
        workflow.atomic_json(self.plan_path, self.plan)
        agent, task = self.plan["agents"]["codex"], self.plan["tasks"][0]
        key = self.root / "key"
        key.write_bytes(bytes(range(32)))
        key.chmod(0o600)
        binary = self.root / "iorec"
        binary.write_bytes(b"test-fixture")
        self.args = workflow.parser().parse_args(["--work-dir", str(self.root / "work"),
            "--task", task["path"], "--task-image", task["image"], "--model", agent["model"],
            "--upstream", agent["upstream"], "--key-file", str(key), "--iorec", str(binary),
            "--verifier-timeout", "900", "--recording-mode", "off",
            "--experiment-plan", str(self.plan_path), "--experiment-case", "paired-off"])
        self.fresh = {"uploads": {"/opt/iorec-agent/codex": {"sha256": agent["artifact"]["sha256"]},
                                  "/tmp/iorec-bin": {"sha256": self.plan["recorder"]["sha256"]}},
                      "task": {"sha256": task["source_tree_sha256"]}, "task_image_override": {"pinned_reference": task["image"]},
                      "harbor": {"launcher": {"path": "/fixture/harbor"}}}

    def test_binds_full_plan_hash_case_and_expected_reported_identity(self):
        bound = plans.bind_case(self.args, self.fresh)
        self.assertEqual(bound["plan_sha256"], workflow.digest(self.plan_path))
        self.assertEqual(bound["case_id"], "paired-off")
        self.assertEqual(bound["expected_result"]["agent_version"], "0.154.0")
        self.assertEqual(bound["expected_result"]["model"], "openai/test-model")

    def test_binds_namespaced_reported_name_from_frozen_task_config(self):
        self.fresh["task"]["harbor_name"] = "terminal-bench/cancel-async-tasks"
        bound = plans.bind_case(self.args, self.fresh)
        self.assertEqual(bound["expected_result"]["task"], "terminal-bench/cancel-async-tasks")

    def test_wrong_case_mode_model_task_artifact_timeout_and_partial_flags_reject(self):
        for field, value in (("experiment_case", "missing"), ("experiment_case", "paired-on"),
                             ("model", "openai/other"), ("agent_timeout", 899), ("task_image", None),
                             ("task", None), ("experiment_case", None), ("experiment_plan", None)):
            args = copy.copy(self.args)
            setattr(args, field, value)
            with self.subTest(field=field), self.assertRaises(plans.PlanFailure):
                plans.bind_case(args, self.fresh)
        self.fresh["uploads"]["/tmp/iorec-bin"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(plans.PlanFailure, "artifacts_differ"):
            plans.bind_case(self.args, self.fresh)

    def test_incomplete_plan_preflight_stops_before_job_commands_or_launch(self):
        self.plan["agents"]["codex"]["model"] = None
        workflow.atomic_json(self.plan_path, self.plan)
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            with mock.patch.object(workflow, "fresh_identity", return_value=self.fresh), mock.patch.object(w, "command") as command, \
                    mock.patch.object(workflow.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(plans.PlanFailure, "declaration_incomplete_no_launch"):
                    w.run()
                command.assert_not_called()
                launch.assert_not_called()
            self.assertNotIn("launch_intent", w.state)
            self.assertFalse(workflow.read_json(work.path / "report.json")["qualification_passed"])

    def test_plan_drift_blocks_before_launch_and_after_terminal_job_without_resubmit(self):
        bound = plans.bind_case(self.args, self.fresh)
        self.plan["budget"]["total_usd"] = "15.00"
        workflow.atomic_json(self.plan_path, self.plan)
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            w.state["config"] = {"fresh_inputs": self.fresh, "experiment": bound,
                                 "key_fingerprint": workflow.digest(self.args.key_file)}
            with mock.patch.object(workflow, "fresh_identity", return_value=self.fresh), \
                    mock.patch.object(workflow.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(workflow.Failure, "experiment_plan_changed"):
                    w.record()
                self.assertNotIn("launch_intent", w.state)
                job = work.path / "jobs/audit"
                (job / "fixture-trial").mkdir(parents=True)
                workflow.atomic_json(job / "result.json", {})
                workflow.atomic_json(job / "fixture-trial/result.json", {})
                w.state["launch_intent"] = {"pid": 999999}
                with self.assertRaisesRegex(workflow.Failure, "experiment_plan_changed"):
                    w.record()
                launch.assert_not_called()

    def test_wrong_reported_agent_version_fails_but_retains_trial_cost(self):
        with workflow.Workspace(self.args.work_dir) as work:
            w = workflow.Workflow(self.args, work)
            w.state["config"] = {"experiment": plans.bind_case(self.args, self.fresh)}
            w.state["launch_intent"] = {"pid": 999999}
            job = work.path / "jobs/audit"
            trial = job / "fixture-trial"
            trial.mkdir(parents=True)
            workflow.atomic_json(job / "result.json", {})
            workflow.atomic_json(trial / "result.json", {"finished_at": "fixture", "task_name": "cancel-async-tasks",
                "agent_info": {"name": "codex", "version": "wrong-version", "model_info": {"provider": "openai", "name": "test-model"}},
                "agent_result": {"cost_usd": 0.5}, "verifier_result": {"rewards": {"reward": 0}}})
            with mock.patch.object(w, "assert_fresh_inputs"):
                with self.assertRaisesRegex(workflow.Failure, "reported_trial_identity"):
                    w.record()
            self.assertEqual(w.state["trial_summary"]["reported_cost_usd"], 0.5)


if __name__ == "__main__":
    unittest.main()
