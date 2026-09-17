#!/usr/bin/python3
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("agentsight_bridge.py")
SPEC = importlib.util.spec_from_file_location("agentsight_bridge", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


def outer(data: dict[str, object], *, pid: int = 0, source: str = "diagnostic", comm: str = "process") -> bytes:
    return (
        json.dumps(
            {"timestamp": 1, "source": source, "pid": pid, "comm": comm, "data": data},
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = bridge.BridgeConfig(
            upstream_path=Path("/bin/true"),
            upstream_sha256="sha256:" + "0" * 64,
            upstream_release="v1.0.25",
            privilege_mode="none",
            sudo_path=None,
            readiness_timeout_seconds=2,
            shutdown_drain_seconds=0,
            max_event_bytes=bridge.MAX_EVENT_BYTES,
        )
        self.args = type(
            "Args",
            (),
            {
                "target_pid": os.getpid(),
                "target_executable_sha256": "sha256:" + "1" * 64,
                "target_cgroup": Path("/sys/fs/cgroup/test"),
                "cgroup_relative": "/test",
            },
        )()

    def test_ready_process_file_network_and_overflow_are_converted(self) -> None:
        output = io.BytesIO()
        parser = bridge.Bridge(self.args, self.config, output)
        parser.process_line(b"Raw Process Events\n")
        parser.process_line(b"================================================\n")
        parser.process_line(
            b"Starting process event stream with raw JSON output (press Ctrl+C to stop):\n"
        )
        parser.process_line(
            outer({"timestamp": 1, "event": "CLOCK_SYNC", "phase": "start"})
        )
        process = outer(
            {
                "timestamp": 2,
                "event": "EXEC",
                "comm": "test",
                "pid": os.getpid(),
                "ppid": 1,
                "filename": "/bin/test",
            },
            pid=os.getpid(),
            source="process",
            comm="test",
        )
        parser.process_line(process)
        parser.process_line(
            outer(
                {
                    "timestamp": 3,
                    "event": "SUMMARY",
                    "comm": "test",
                    "pid": os.getpid(),
                    "type": "NET_CONNECT",
                    "detail": "127.0.0.1:443",
                    "count": 1,
                },
                pid=os.getpid(),
                source="process",
                comm="test",
            )
        )
        parser.process_line(
            outer(
                {
                    "timestamp": 0,
                    "event": "WARNING",
                    "comm": "",
                    "pid": 0,
                    "type": "AGG_MAP_OVERFLOW",
                    "overflow_count": 7,
                },
                source="process",
                comm="",
            )
        )
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(records[0]["type"], "ready")
        self.assertEqual(records[1]["reason"], "upstream_ring_buffer_loss_unobservable")
        evidence = [record for record in records if record["type"] == "evidence"]
        self.assertEqual(
            [record["event"] for record in evidence],
            ["agentsight_process_lifecycle", "agentsight_network_activity"],
        )
        self.assertEqual(evidence[1]["direction"], "net_connect")
        self.assertEqual(base64.b64decode(evidence[0]["payload_base64"]), process.strip())
        self.assertEqual(
            evidence[0]["payload_sha256"],
            "sha256:" + hashlib.sha256(process.strip()).hexdigest(),
        )
        self.assertEqual(records[-1]["reason"], "upstream_aggregate_map_overflow")
        self.assertEqual(records[-1]["occurrences"], 7)

    def test_end_anchor_before_start_is_a_gap_not_readiness(self) -> None:
        output = io.BytesIO()
        parser = bridge.Bridge(self.args, self.config, output)
        parser.process_line(
            outer({"timestamp": 1, "event": "CLOCK_SYNC", "phase": "end"})
        )
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertFalse(parser.ready)
        self.assertFalse(parser.saw_end_anchor)
        self.assertEqual(records[0]["reason"], "upstream_end_anchor_before_start")

    def test_stderr_problem_marker_split_across_chunks_is_detected(self) -> None:
        parser = bridge.Bridge(self.args, self.config, io.BytesIO())

        class SplitStream:
            def __init__(self) -> None:
                self.chunks = iter((b"prefix fa", b"iled suffix", b""))

            def read(self, _size: int) -> bytes:
                return next(self.chunks)

        parser._read_stderr(SplitStream())
        self.assertTrue(parser.stderr_problem)

    def test_outside_cgroup_and_schema_drift_become_gaps(self) -> None:
        output = io.BytesIO()
        parser = bridge.Bridge(self.args, self.config, output)
        parser.process_line(
            outer({"timestamp": 1, "event": "CLOCK_SYNC", "phase": "start"})
        )
        parser.process_line(b'{"unexpected":true}\n')
        parser.process_line(
            outer(
                {"timestamp": 2, "event": "EXEC", "comm": "other", "pid": 2_147_483_647},
                pid=2_147_483_647,
                source="process",
                comm="other",
            )
        )
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        reasons = [record["reason"] for record in records if record["type"] == "gap"]
        self.assertIn("upstream_event_schema_changed", reasons)
        self.assertIn("upstream_event_outside_target_cgroup", reasons)
        self.assertFalse(any(record["type"] == "evidence" for record in records))


class ConfigTests(unittest.TestCase):
    def test_noninteractive_sudo_requires_root_owned_upstream_chain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-agentsight-config-") as directory:
            root = Path(directory)
            config_path = root / "config.json"
            upstream = Path("/usr/bin/true").resolve()
            sudo = Path("/usr/bin/sudo").resolve()
            config_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "upstream_path": str(upstream),
                        "upstream_sha256": "sha256:"
                        + hashlib.sha256(upstream.read_bytes()).hexdigest(),
                        "upstream_release": "test-v1",
                        "privilege_mode": "sudo-noninteractive",
                        "sudo_path": str(sudo),
                        "readiness_timeout_seconds": 2,
                        "shutdown_drain_seconds": 0,
                        "max_event_bytes": bridge.MAX_EVENT_BYTES,
                    }
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o600)
            loaded = bridge.load_config(config_path)
            self.assertEqual(loaded.upstream_path, upstream)
            self.assertEqual(loaded.sudo_path, sudo)

            user_upstream = root / "user-upstream"
            user_upstream.write_bytes(upstream.read_bytes())
            user_upstream.chmod(0o700)
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            raw["upstream_path"] = str(user_upstream)
            raw["upstream_sha256"] = (
                "sha256:" + hashlib.sha256(user_upstream.read_bytes()).hexdigest()
            )
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(bridge.BridgeError, "owner is not accepted"):
                bridge.load_config(config_path)

    def test_config_rejects_digest_mismatch_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-agentsight-config-") as directory:
            root = Path(directory)
            upstream = root / "upstream"
            upstream.write_bytes(b"#!/bin/sh\nexit 0\n")
            upstream.chmod(0o700)
            raw = {
                "schema_version": 1,
                "upstream_path": str(upstream),
                "upstream_sha256": "sha256:" + "0" * 64,
                "upstream_release": "test-v1",
                "privilege_mode": "none",
                "sudo_path": None,
                "readiness_timeout_seconds": 2,
                "shutdown_drain_seconds": 0,
                "max_event_bytes": bridge.MAX_EVENT_BYTES,
            }
            config_path = root / "config.json"
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            config_path.chmod(0o600)
            with self.assertRaisesRegex(bridge.BridgeError, "digest does not match"):
                bridge.load_config(config_path)
            raw["unexpected"] = True
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(bridge.BridgeError, "fields do not match"):
                bridge.load_config(config_path)


class ProcessBridgeTests(unittest.TestCase):
    def test_fake_upstream_handshake_evidence_gap_and_orderly_final(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-agentsight-bridge-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            upstream = root / "fake-agentsight.py"
            upstream.write_text(
                "#!/usr/bin/python3\n"
                "import json,signal,sys,time\n"
                "stop=False\n"
                "def done(*_):\n global stop; stop=True\n"
                "signal.signal(signal.SIGINT,done)\n"
                "pid=int(sys.argv[sys.argv.index('--seed-pid')+1])\n"
                "def emit(data,pid=0,source='diagnostic',comm='process'):\n"
                " print(json.dumps({'timestamp':1,'source':source,'pid':pid,'comm':comm,'data':data},separators=(',',':')),flush=True)\n"
                "print('Raw Process Events',flush=True)\n"
                "print('-'*48,flush=True)\n"
                "emit({'timestamp':1,'event':'CLOCK_SYNC','phase':'start'})\n"
                "emit({'timestamp':2,'event':'EXEC','comm':'target','pid':pid,'ppid':1,'filename':'/bin/target'},pid,'process','target')\n"
                "while not stop: time.sleep(0.01)\n"
                "emit({'timestamp':3,'event':'CLOCK_SYNC','phase':'end'})\n",
                encoding="utf-8",
            )
            upstream.chmod(0o700)
            digest = "sha256:" + hashlib.sha256(upstream.read_bytes()).hexdigest()
            config = bridge.BridgeConfig(
                upstream_path=upstream,
                upstream_sha256=digest,
                upstream_release="test",
                privilege_mode="none",
                sudo_path=None,
                readiness_timeout_seconds=2,
                shutdown_drain_seconds=0,
                max_event_bytes=bridge.MAX_EVENT_BYTES,
            )
            (root / "cgroup.procs").write_text(str(os.getpid()) + "\n", encoding="ascii")
            args = type(
                "Args",
                (),
                {
                    "target_pid": os.getpid(),
                    "target_executable_sha256": "sha256:" + "1" * 64,
                    "target_cgroup": root,
                    "cgroup_relative": "/test",
                },
            )()
            output = io.BytesIO()
            parser = bridge.Bridge(args, config, output)
            result: list[int] = []
            thread = threading.Thread(target=lambda: result.append(parser.run()))
            thread.start()
            deadline = time.monotonic() + 2
            while b'"type":"ready"' not in output.getvalue() and time.monotonic() < deadline:
                time.sleep(0.01)
            parser.request_stop(signal.SIGINT, None)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, [0])
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(records[0]["type"], "ready")
            self.assertEqual(records[1]["reason"], "upstream_ring_buffer_loss_unobservable")
            self.assertEqual(sum(record["type"] == "evidence" for record in records), 1)
            final = records[-1]
            self.assertEqual(final["type"], "final")
            self.assertEqual(final["captured_events"], 1)
            self.assertEqual(final["dropped_events"], 1)
            self.assertEqual(final["probe_hits"], 1)
            self.assertFalse(final["complete"])

    def test_silent_upstream_obeys_readiness_deadline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-agentsight-bridge-") as directory:
            root = Path(directory)
            upstream = root / "silent.py"
            upstream.write_text(
                "#!/usr/bin/python3\n"
                "import signal,time\n"
                "stop=False\n"
                "def done(*_):\n global stop; stop=True\n"
                "signal.signal(signal.SIGINT,done)\n"
                "while not stop: time.sleep(0.01)\n",
                encoding="utf-8",
            )
            upstream.chmod(0o700)
            config = bridge.BridgeConfig(
                upstream_path=upstream,
                upstream_sha256="sha256:"
                + hashlib.sha256(upstream.read_bytes()).hexdigest(),
                upstream_release="test",
                privilege_mode="none",
                sudo_path=None,
                readiness_timeout_seconds=1,
                shutdown_drain_seconds=0,
                max_event_bytes=bridge.MAX_EVENT_BYTES,
            )
            args = type(
                "Args",
                (),
                {
                    "target_pid": os.getpid(),
                    "target_cgroup": root,
                    "cgroup_relative": "/test",
                },
            )()
            parser = bridge.Bridge(args, config, io.BytesIO())
            started = time.monotonic()
            with self.assertRaisesRegex(bridge.BridgeError, "readiness deadline expired"):
                parser.run()
            self.assertLess(time.monotonic() - started, 4)


if __name__ == "__main__":
    unittest.main()
