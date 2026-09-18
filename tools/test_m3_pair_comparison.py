from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import harbor_audit_workflow as workflow
from harbor_input_provenance import audit_definitions, file_identity, image_compose, measurement_definitions
import m3_pair_comparison as pair
from m3_experiment_plan import bind_case


class PairComparisonTests(unittest.TestCase):
    """Entirely synthetic workspaces: no provider, real trial or crypto audit."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan_path = self.root / "plan.json"
        self.plan = json.loads((workflow.ROOT / "examples/m3-experiment-plan.json").read_text())
        for name, agent in self.plan["agents"].items():
            agent["model"] = audit_definitions().AGENTS[name]["provider"] + "/fixture"
        self.plan["budget"].update(total_usd="14", per_trial_usd="1", approval_reference="synthetic-test-not-authorization",
                                    provider_cap_evidence_sha256="a" * 64)
        workflow.atomic_json(self.plan_path, self.plan)
        self.roots = {mode: self.root / mode for mode in ("off", "on")}
        self.states = {}
        self.trials = {}
        for mode in self.roots:
            self.make_case(mode)

    def make_case(self, mode):
        root = self.roots[mode]
        root.mkdir(mode=0o700)
        (root / ".lock").touch(mode=0o600)
        agent = self.plan["agents"]["codex"]
        task = self.plan["tasks"][0]
        overlay = root / "task-image.compose.json"
        workflow.atomic_json(overlay, image_compose(task["image"]))
        fresh = {"agent": "codex", "upstream": agent["upstream"], "recording_mode": mode,
                 "task": {"sha256": task["source_tree_sha256"]},
                 "task_image_override": {"pinned_reference": task["image"]},
                 "cli_wrapper_sha256": hashlib.sha256(audit_definitions().cli_wrapper("codex", agent["upstream"], mode).encode()).hexdigest(),
                 "uploads": {"/opt/iorec-agent/codex": {"sha256": agent["artifact"]["sha256"]},
                             "/tmp/iorec-bin": {"sha256": self.plan["recorder"]["sha256"]},
                             "/opt/iorec-agent/measure.py": file_identity(workflow.ROOT / "examples/harbor_audit_measure.py")},
                 "controller": {"fixture_only": "identical-test-input"}, "harbor": {"package_version": "fixture-only"}}
        cfg = {"agent": "codex", "agent_budget_usd": None, "agent_timeout": 900, "verifier_timeout": 900,
               "api": "http://127.0.0.1:18080", "web": "http://127.0.0.1:8088", "mode": "fresh_trial",
               "recording_mode": mode, "source": task["path"], "model": agent["model"], "upstream": agent["upstream"],
               "harbor_version": "fixture-only", "iorec_sha256": self.plan["recorder"]["sha256"],
               "key_fingerprint": "fake-secret-not-for-output", "task_image_compose": file_identity(overlay),
               "fresh_inputs": fresh, "fresh_inputs_sha256": pair.canonical_hash(fresh)}
        args = SimpleNamespace(agent="codex", agent_budget_usd=None, agent_timeout=900, verifier_timeout=900,
                               model=agent["model"], task=Path(task["path"]), task_image=task["image"],
                               upstream=agent["upstream"], recording_mode=mode,
                               experiment_plan=self.plan_path, experiment_case="paired-" + mode)
        cfg["experiment"] = bind_case(args, fresh)
        workflow.atomic_json(root / "harbor-config.json", workflow.harbor_config(args, root))
        trial = root / "jobs/audit" / ("cancel-async-tasks__fixture-" + mode)
        trial.mkdir(parents=True)
        self.trials[mode] = trial
        minute = "00" if mode == "off" else "01"
        stamp = lambda sec: "2026-09-18T12:" + minute + ":" + sec + "+00:00"
        r = {"started_at": stamp("00"), "finished_at": stamp("50"), "task_name": task["id"],
             "agent_info": {"name": "codex", "version": agent["version"], "model_info": {"provider": "openai", "name": "fixture"}},
             "agent_result": {"cost_usd": 0.2}, "verifier_result": {"rewards": {"reward": 0}},
             "environment_setup": {"started_at": stamp("00"), "finished_at": stamp("05")},
             "agent_setup": {"started_at": stamp("05"), "finished_at": stamp("10")},
             "agent_execution": {"started_at": stamp("10"), "finished_at": stamp("40")},
             "verifier": {"started_at": stamp("40"), "finished_at": stamp("50")}}
        workflow.atomic_json(trial / "result.json", r)
        workflow.atomic_json(trial.parent / "result.json", {"finished_at": stamp("51")})
        benchmark, provenance = workflow.benchmark_from_trial(trial)
        observer = measurement_definitions()
        invocation = ("0" if mode == "off" else "1") * 32
        destination = trial / "agent/iorec-measurements" / invocation
        destination.mkdir(parents=True, mode=0o700)
        header = {"schema_version": 1, "invocation_id": invocation, "recording_mode": mode,
                  "resource_scope": observer.RESOURCE_SCOPE, "wall_scope": observer.WALL_SCOPE,
                  "started_at": stamp("11"), "observer_python_version": "3.13.0",
                  "declared_network_mode": "container_native" if mode == "off" else "recorder_task_netns_transparent_proxy"}
        observer.publish(destination, "started.json", {**header, "measurement_status": "started"})
        observer.publish(destination, "result.json", {**header, "measurement_status": "completed", "exit_code": 0,
            "terminating_signal": None, "wall_seconds": 10 if mode == "off" else 12,
            "user_cpu_seconds": 2 if mode == "off" else 3, "system_cpu_seconds": 0,
            "max_rss_kib": 1024 if mode == "off" else 2048, "observer_signal_count": 0, "observer_signals": []})
        metrics = observer.read_trial_measurement(trial, mode)
        for name in ("audit-package-inventory.tsv", "audit-tool-sha256.txt"):
            (trial / "agent" / name).write_text("identical-synthetic-inventory\n")
        source = {"benchmark": benchmark, "measurement": metrics}
        stages = {name: {"status": "completed", "result": {}} for name in ("preflight", "record", "admission")}
        stages["admission"]["result"] = {"reservation_id": "a" * 32}
        if mode == "off":
            source["recording_mode"] = "off"
        else:
            run = trial / "agent/iorec-runs/run-fixture"
            run.mkdir(parents=True)
            (run / "manifest.json").write_text("fixture-not-real-capture\n")
            (run / "events.jsonl").write_text("fixture-not-real-capture\n")
            source.update(run_id="run-fixture", manifest_sha256=workflow.digest(run / "manifest.json"), events_sha256=workflow.digest(run / "events.jsonl"))
            for name, result in (("integrity", {"passed": True}),
                    ("transport_audit", {"complete": True, "payload_diff_passed": True, "gaps_count": 0}),
                    ("import", {"sealed": True, "capture_run_id": "run-fixture"}),
                    ("platform", {"transport_proof_status": "verified"})):
                stages[name] = {"status": "completed", "result": result}
        stages["record"]["result"] = {**source, **provenance, "fresh_trial": True, "fresh_inputs_unchanged": True}
        self.states[mode] = {"config": cfg, "status": "baseline_completed" if mode == "off" else "completed",
                             "source_identity": source, "stages": stages, "trial_summary": {"benchmark": benchmark, **provenance},
                             "plaintext_staging_cleaned": True,
                             "launch_intent": {"pid": 12345, "automatic_retries": 0, "ledger_reservation_id": "a" * 32,
                                "experiment": {k: cfg["experiment"][k] for k in ("case_id", "plan_sha256")}}}
        self.save(mode)

    def save(self, mode):
        state = self.states[mode]
        state["config"]["fresh_inputs_sha256"] = pair.canonical_hash(state["config"]["fresh_inputs"])
        state["stages"]["preflight"]["result"] = {"mode": "fresh_trial", "iorec_sha256": state["config"]["iorec_sha256"],
            "fresh_inputs_sha256": state["config"]["fresh_inputs_sha256"]}
        report = {"workflow_status": state["status"], "recording_mode": mode, "qualification_passed": mode == "on",
                  "baseline_completed": mode == "off", "plaintext_staging_cleaned": True,
                  "source": state["source_identity"], "stages": state["stages"], "trial_summary": state["trial_summary"]}
        workflow.atomic_json(self.roots[mode] / "state.json", state)
        workflow.atomic_json(self.roots[mode] / "report.json", report)

    def compare(self):
        return pair.compare(self.roots["off"], self.roots["on"], self.plan_path)

    def test_comparison_scopes_math_zero_denominator_and_no_secret(self):
        r = self.compare()
        self.assertTrue(r["paired_metrics_compared"])
        self.assertFalse(r["qualification_passed"])
        self.assertFalse(r["m3_complete"])
        self.assertFalse(r["billing_verified"])
        self.assertEqual(r["metric_comparison"]["wall_seconds"], {"off": 10, "on": 12, "on_minus_off": 2, "on_divided_by_off": 1.2})
        self.assertIsNone(r["metric_comparison"]["system_cpu_seconds"]["on_divided_by_off"])
        self.assertEqual(r["cases"]["off"]["harbor_stage_seconds"]["agent_setup"], 5)
        self.assertEqual(r["cases"]["on"]["benchmark"]["reward"], 0)
        self.assertNotIn("fake-secret", json.dumps(r))
        self.assertEqual(r["network_dependency_impact"], "not_determined_from_summary")

    def test_plan_missing_models_and_changed_model_task_artifact_timeout_refuse(self):
        original = copy.deepcopy(self.plan)
        for mutate in (lambda p: p["agents"]["codex"].update(model=None),
                       lambda p: p["agents"]["codex"].update(model="openai/other"),
                       lambda p: p["agents"]["codex"]["artifact"].update(sha256="0" * 64),
                       lambda p: p["tasks"][0].update(source_tree_sha256="0" * 64),
                       lambda p: p["limits"].update(agent_timeout_seconds=899),
                       lambda p: p["limits"].update(setup_timeout_seconds=599)):
            changed = copy.deepcopy(original)
            mutate(changed)
            workflow.atomic_json(self.plan_path, changed)
            with self.assertRaises(pair.ComparisonFailure):
                self.compare()

    def test_same_workspace_unfinished_state_and_missing_stage_refuse(self):
        with self.assertRaisesRegex(pair.ComparisonFailure, "distinct"):
            pair.compare(self.roots["on"], self.roots["on"], self.plan_path)
        self.states["on"]["status"] = "running"
        self.save("on")
        with self.assertRaisesRegex(pair.ComparisonFailure, "not_completed"):
            self.compare()
        self.states["on"]["status"] = "completed"
        del self.states["on"]["stages"]["platform"]
        self.save("on")
        with self.assertRaisesRegex(pair.ComparisonFailure, "stages"):
            self.compare()

    def test_changed_controller_or_runtime_inventory_refuse(self):
        self.states["on"]["config"]["fresh_inputs"]["controller"]["fixture_only"] = "different-version"
        self.save("on")
        with self.assertRaisesRegex(pair.ComparisonFailure, "pair_inputs_differ"):
            self.compare()
        self.states["on"]["config"]["fresh_inputs"]["controller"]["fixture_only"] = "identical-test-input"
        self.save("on")
        (self.trials["on"] / "agent/audit-package-inventory.tsv").write_text("different-package\n")
        with self.assertRaisesRegex(pair.ComparisonFailure, "packages_or_tools"):
            self.compare()

    def test_launch_configuration_and_input_hash_drift_refuse(self):
        path = self.roots["on"] / "harbor-config.json"
        cfg = pair.json_file(path)
        cfg["retry"]["max_retries"] = 1
        workflow.atomic_json(path, cfg)
        with self.assertRaisesRegex(pair.ComparisonFailure, "launch_configuration"):
            self.compare()
        self.states["off"]["config"]["fresh_inputs_sha256"] = "0" * 64
        workflow.atomic_json(self.roots["off"] / "state.json", self.states["off"])
        with self.assertRaisesRegex(pair.ComparisonFailure, "digest_mismatch"):
            self.compare()

    def test_changed_trial_metrics_or_capture_index_refuse(self):
        path = next((self.trials["on"] / "agent/iorec-measurements").glob("*/result.json"))
        original = path.read_bytes()
        data = json.loads(original)
        data["wall_seconds"] = 999
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(pair.ComparisonFailure, "measurement_artifact_changed"):
            self.compare()
        path.write_bytes(original)
        (self.trials["on"] / "agent/iorec-runs/run-fixture/events.jsonl").write_text("changed")
        with self.assertRaisesRegex(pair.ComparisonFailure, "capture_index_changed"):
            self.compare()

    def test_recorded_proof_missing_baseline_capture_and_reversed_order_refuse(self):
        self.states["on"]["stages"]["transport_audit"]["result"]["complete"] = False
        self.save("on")
        with self.assertRaisesRegex(pair.ComparisonFailure, "proof_missing"):
            self.compare()
        self.states["on"]["stages"]["transport_audit"]["result"]["complete"] = True
        self.save("on")
        capture = self.trials["off"] / "agent/iorec-runs/unfinished"
        capture.mkdir(parents=True)
        with self.assertRaisesRegex(pair.ComparisonFailure, "baseline_has_capture"):
            self.compare()
        capture.rmdir()
        self.plan["paired"]["order"] = ["on", "off"]
        workflow.atomic_json(self.plan_path, self.plan)
        for mode in self.roots:
            self.states[mode]["config"]["experiment"]["plan_sha256"] = workflow.digest(self.plan_path)
            self.states[mode]["launch_intent"]["experiment"]["plan_sha256"] = workflow.digest(self.plan_path)
            self.save(mode)
        with self.assertRaisesRegex(pair.ComparisonFailure, "order_or_serial"):
            self.compare()

    def test_unknown_or_excessive_costs_stop_without_becoming_zero(self):
        for cost in (None, 2):
            result_path = self.trials["off"] / "result.json"
            result = pair.json_file(result_path)
            result["agent_result"]["cost_usd"] = cost
            workflow.atomic_json(result_path, result)
            benchmark, provenance = workflow.benchmark_from_trial(self.trials["off"])
            s = self.states["off"]
            s["source_identity"]["benchmark"] = benchmark
            s["stages"]["record"]["result"]["benchmark"] = benchmark
            s["stages"]["record"]["result"].update(provenance)
            s["trial_summary"] = {"benchmark": benchmark, **provenance}
            self.save("off")
            r = self.compare()
            self.assertTrue(r["stop_further_paid_trials"])
            self.assertFalse(r["reported_costs_within_per_trial_limit"])
            self.assertEqual(r["cases"]["off"]["reported_cost_usd"], cost)

    def test_live_lock_symlink_and_fifo_refuse_without_mutation(self):
        with (self.roots["off"] / ".lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(pair.ComparisonFailure, "still_running"):
                self.compare()
        target = self.trials["on"] / "agent/audit-tool-sha256.txt"
        target.unlink()
        target.symlink_to(self.plan_path)
        with self.assertRaisesRegex(pair.ComparisonFailure, "symlink"):
            self.compare()
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(Exception):
            self.compare()

    def test_plan_must_be_bound_to_launch_and_job_must_have_one_terminal_trial(self):
        self.states["on"]["launch_intent"]["experiment"]["plan_sha256"] = "0" * 64
        self.save("on")
        with self.assertRaisesRegex(pair.ComparisonFailure, "plan_not_bound"):
            self.compare()
        self.states["on"]["launch_intent"]["experiment"]["plan_sha256"] = workflow.digest(self.plan_path)
        self.save("on")
        job_result = self.trials["on"].parent / "result.json"
        before = job_result.read_bytes()
        workflow.atomic_json(job_result, {"finished_at": None})
        with self.assertRaisesRegex(pair.ComparisonFailure, "trial_timestamp"):
            self.compare()
        job_result.write_bytes(before)
        extra = self.trials["on"].parent / "extra-trial"
        extra.mkdir()
        workflow.atomic_json(extra / "result.json", {})
        with self.assertRaisesRegex(pair.ComparisonFailure, "exactly_one_terminal"):
            self.compare()

    def test_report_state_disagreement_and_unfinished_cleanup_refuse(self):
        path = self.roots["on"] / "report.json"
        report = pair.json_file(path)
        report["trial_summary"]["reported_cost_usd"] = 999
        workflow.atomic_json(path, report)
        with self.assertRaisesRegex(pair.ComparisonFailure, "state_report_disagree"):
            self.compare()
        self.states["on"]["plaintext_staging_cleaned"] = False
        self.save("on")
        with self.assertRaisesRegex(pair.ComparisonFailure, "cleanup_not_complete"):
            self.compare()

    def test_cli_private_publication_is_exclusive_and_outside_evidence(self):
        command = [sys.executable, str(workflow.ROOT / "tools/m3_pair_comparison.py"),
                   "--off-work-dir", str(self.roots["off"]), "--on-work-dir", str(self.roots["on"]),
                   "--plan", str(self.plan_path), "--output"]
        path = self.root / "comparison.json"
        first = subprocess.run([*command, str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = path.read_bytes()
        again = subprocess.run([*command, str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(again.returncode, 1)
        self.assertEqual(path.read_bytes(), before)
        inside = subprocess.run([*command, str(self.roots["off"] / "must-not-write.json")], capture_output=True, timeout=10)
        self.assertEqual(inside.returncode, 1)
        self.assertFalse((self.roots["off"] / "must-not-write.json").exists())


if __name__ == "__main__":
    unittest.main()
