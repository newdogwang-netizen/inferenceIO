#!/usr/bin/python3
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("ecapture_bridge.py")
SPEC = importlib.util.spec_from_file_location("ecapture_bridge", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class HexParserTests(unittest.TestCase):
    def test_decodes_exact_upstream_hex_dump(self) -> None:
        lines = [
            "0000  474554202F204854 54502F312E310D0A  486F73743A206578 616D706C652E636F    GET / HTTP/1.1..Host: example.co",
            "0020  6D0D0A557365722D 4167656E743A2063  75726C2F382E3134 2E310D0A41636365    m..User-Agent: curl/8.14.1..Acce",
            "0040  70743A202A2F2A0D 0A0D0A                            pt: */*....                     ",
        ]
        payload = bridge._decode_hex(lines, 75)
        self.assertEqual(payload, b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.14.1\r\nAccept: */*\r\n\r\n")

    def test_rejects_length_or_offset_disagreement(self) -> None:
        with self.assertRaises(bridge.BridgeError):
            bridge._decode_hex(["0000  00                              ."], 2)
        with self.assertRaises(bridge.BridgeError):
            bridge._decode_hex(["0020  00                              ."], 1)


class ParserSignalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = bridge.BridgeConfig(
            Path("/bin/true"), "sha256:" + "0" * 64, "v2.6.0", "tls", None, 4096, 10, 20, 0, 1024
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

    def test_records_loss_and_emits_exact_payload(self) -> None:
        output = io.BytesIO()
        parser = bridge.Bridge(self.args, self.config, output)
        parser.allowed_pids.add(123)
        parser.process_line(b"2026 INF probe started successfully.\n")
        parser.process_line(b"2026 WRN Perf buffer full, samples lost lost_samples=7\n")
        parser.process_line(
            b"2026-09-16T00:00:00Z INF [2026-09-16 00:00:00.000] "
            b"PID:123 TID:124 Comm:curl FD:4 WRITE (5 bytes, hex):\n"
        )
        parser.process_line(b"0000  68656C6C6F                                   hello\n")
        parser.finish_event()
        parser.process_line(b"2026 INF PID:123 TID:124 Comm:curl FD:4 READ (0 bytes, hex):\n")
        parser.finish_event()
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(records[0]["type"], "ready")
        self.assertEqual(records[1], {"type": "gap", "schema_version": 2, "reason": "ring_buffer_samples_lost", "occurrences": 7})
        self.assertEqual(records[2]["payload_base64"], "aGVsbG8=")
        self.assertEqual(records[2]["payload_sha256"], "sha256:" + hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(parser.drops, 7)
        self.assertEqual(parser.events, 1)
        self.assertEqual(parser.probe_hits, 2)

    def test_debug_echo_cannot_trigger_readiness_or_payload_parsing(self) -> None:
        output = io.BytesIO()
        parser = bridge.Bridge(self.args, self.config, output)
        parser.process_line(b"2026-09-16T00:00:00Z DBG probe started successfully.\n")
        parser.process_line(
            b"2026-09-16T00:00:00Z DBG PID:123 TID:124 Comm:curl FD:4 WRITE (5 bytes, hex):\n"
        )
        parser.process_line(b"0000  68656C6C6F                                   hello\n")
        self.assertFalse(parser.ready)
        self.assertIsNone(parser.pending)
        self.assertEqual(output.getvalue(), b"")

    def test_unbounded_loss_counter_is_safely_saturated(self) -> None:
        output = io.BytesIO()
        parser = bridge.Bridge(self.args, self.config, output)
        parser.process_line(
            b"2026 WRN Perf buffer full, samples lost lost_samples="
            + b"9" * 5000
            + b"\n"
        )
        record = json.loads(output.getvalue())
        self.assertEqual(record["occurrences"], bridge.MAX_OCCURRENCES)
        self.assertEqual(parser.drops, bridge.MAX_OCCURRENCES)

    def test_gotls_contiguous_hex_preserves_payload_and_tuple_identity(self) -> None:
        output = io.BytesIO()
        config = bridge.BridgeConfig(
            Path("/bin/true"), "sha256:" + "0" * 64, "v2.6.0", "gotls", None, 4096, 10, 20, 0, 1024
        )
        parser = bridge.Bridge(self.args, config, output)
        parser.allowed_pids.add(123)
        parser.process_line(
            b"2026-09-16T00:00:00Z INF PID:123, TID:124, Comm:go-client, FD:4, "
            b"Tuple:[127.0.0.1]:40000->[127.0.0.1]:443, Type:WRITE, Len:5\n"
        )
        parser.process_line(b"Data(hex):\n")
        parser.process_line(b"68656c6c6f\n")
        parser.process_line(
            b"2026-09-16T00:00:00Z INF PID:123, TID:125, Comm:go-client, FD:4, "
            b"Tuple:[127.0.0.1]:443->[127.0.0.1]:40000, Type:READ, Len:5\n"
        )
        parser.process_line(b"Data(hex):\n")
        parser.process_line(b"776f726c64\n")
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["payload_base64"], "aGVsbG8=")
        self.assertEqual(records[1]["payload_base64"], "d29ybGQ=")
        self.assertEqual(records[0]["direction"], "write")
        self.assertEqual(records[1]["direction"], "read")
        tuple_value = "[127.0.0.1]:40000<->[127.0.0.1]:443"
        expected_id = "ecapture-" + hashlib.sha256(tuple_value.encode()).hexdigest()[:32]
        self.assertEqual(records[0]["connection_id"], expected_id)
        self.assertEqual(records[1]["connection_id"], expected_id)
        self.assertEqual(parser.events, 2)
        self.assertEqual(parser.probe_hits, 2)

    def test_gotls_rejects_missing_marker_or_length_mismatch(self) -> None:
        output = io.BytesIO()
        config = bridge.BridgeConfig(
            Path("/bin/true"), "sha256:" + "0" * 64, "v2.6.0", "gotls", None, 4096, 10, 20, 0, 1024
        )
        parser = bridge.Bridge(self.args, config, output)
        parser.allowed_pids.add(123)
        header = (
            b"2026-09-16T00:00:00Z INF PID:123, TID:124, Comm:go-client, FD:4, "
            b"Tuple:[127.0.0.1]:40000->[127.0.0.1]:443, Type:READ, Len:5\n"
        )
        parser.process_line(header)
        parser.finish_event()
        parser.process_line(header)
        parser.process_line(b"Data(hex):\n")
        parser.process_line(b"6869\n")
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([record["type"] for record in records], ["gap", "gap"])
        self.assertEqual(parser.events, 0)
        self.assertEqual(parser.drops, 2)


class ConfigurationTests(unittest.TestCase):
    def test_gotls_config_accepts_pinned_upstream_and_forbids_libssl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-ecapture-config-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            upstream = root / "ecapture"
            upstream.write_bytes(b"#!/bin/sh\nexit 0\n")
            upstream.chmod(0o700)
            digest = "sha256:" + hashlib.sha256(upstream.read_bytes()).hexdigest()
            config = root / "config.json"
            raw = {
                "schema_version": 1,
                "upstream_path": str(upstream),
                "upstream_sha256": digest,
                "upstream_release": "test-v1",
                "module": "gotls",
            }
            config.write_text(json.dumps(raw), encoding="utf-8")
            config.chmod(0o600)
            self.assertEqual(bridge.load_config(config).module, "gotls")
            raw["libssl"] = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
            config.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(bridge.BridgeError, "valid only"):
                bridge.load_config(config)


class ProcessBridgeTests(unittest.TestCase):
    def test_fake_upstream_handshake_evidence_and_final(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-ecapture-bridge-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            upstream = root / "fake-ecapture.py"
            upstream.write_text(
                "#!/usr/bin/python3\n"
                "import signal,time\n"
                "stop=False\n"
                "def done(*_):\n global stop; stop=True\n"
                "signal.signal(signal.SIGINT,done)\n"
                "print('2026 INF probe started successfully.',flush=True)\n"
                f"print('2026 INF PID:{os.getpid()} TID:{os.getpid()} Comm:test FD:3 WRITE (5 bytes, hex):',flush=True)\n"
                "print('0000  68656C6C6F                                   hello',flush=True)\n"
                "while not stop: time.sleep(0.02)\n",
                encoding="utf-8",
            )
            upstream.chmod(0o700)
            digest = "sha256:" + hashlib.sha256(upstream.read_bytes()).hexdigest()
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "upstream_path": str(upstream),
                        "upstream_sha256": digest,
                        "upstream_release": "test-v1",
                        "module": "tls",
                        "mapsize_kib": 1024,
                        "readiness_timeout_seconds": 5,
                        "shutdown_drain_seconds": 0,
                    }
                ),
                encoding="utf-8",
            )
            config.chmod(0o600)
            executable = Path("/usr/bin/true").resolve()
            exe_digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
            cgroup_line = Path(f"/proc/{os.getpid()}/cgroup").read_text(encoding="ascii").strip()
            self.assertTrue(cgroup_line.startswith("0::"))
            cgroup = Path("/sys/fs/cgroup") / cgroup_line[3:].lstrip("/")
            process = subprocess.Popen(
                [
                    str(MODULE_PATH),
                    "--config",
                    str(config),
                    "--iorec-probe-protocol",
                    "2",
                    "--target-pid",
                    str(os.getpid()),
                    "--target-executable",
                    str(executable),
                    "--target-executable-sha256",
                    exe_digest,
                    "--filter-scope",
                    "cgroup",
                    "--target-cgroup",
                    str(cgroup),
                    "--run-id",
                    "run-test",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # communicate() reads file descriptors directly. Do not let the
                # readiness readline prefetch evidence into a BufferedReader.
                bufsize=0,
            )
            assert process.stdout is not None
            first = json.loads(process.stdout.readline())
            self.assertEqual(first["type"], "ready")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr.decode())
            records = [json.loads(line) for line in stdout.splitlines()]
            self.assertEqual([record["type"] for record in records], ["evidence", "final"])
            self.assertEqual(records[0]["payload_base64"], "aGVsbG8=")
            self.assertTrue(records[1]["complete"])

    def test_silent_upstream_obeys_readiness_deadline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-ecapture-bridge-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            upstream = root / "silent.py"
            upstream.write_text(
                "#!/usr/bin/python3\n"
                "import signal,time\n"
                "stop=False\n"
                "def done(*_):\n global stop; stop=True\n"
                "signal.signal(signal.SIGINT,done)\n"
                "while not stop: time.sleep(0.02)\n",
                encoding="utf-8",
            )
            upstream.chmod(0o700)
            config = bridge.BridgeConfig(
                upstream,
                "sha256:" + hashlib.sha256(upstream.read_bytes()).hexdigest(),
                "test-v1",
                "tls",
                None,
                1024,
                10,
                1,
                0,
                1024,
            )
            args = type("Args", (), {"target_pid": os.getpid(), "target_cgroup": Path("/sys/fs/cgroup")})()
            parser = bridge.Bridge(args, config, io.BytesIO())
            started = time.monotonic()
            with self.assertRaisesRegex(bridge.BridgeError, "readiness deadline expired"):
                parser.run()
            self.assertLess(time.monotonic() - started, 4)

    def test_fake_gotls_upstream_receives_pinned_target_elf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iorec-ecapture-gotls-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            executable = Path("/usr/bin/true").resolve()
            upstream = root / "fake-ecapture.py"
            upstream.write_text(
                "#!/usr/bin/python3\n"
                "import signal,sys,time\n"
                "stop=False\n"
                "def done(*_):\n global stop; stop=True\n"
                "signal.signal(signal.SIGINT,done)\n"
                "assert sys.argv[1] == 'gotls'\n"
                f"assert '--elfpath={executable}' in sys.argv\n"
                "assert not any(x.startswith('--libssl=') for x in sys.argv)\n"
                "print('2026 INF probe started successfully.',flush=True)\n"
                f"print('2026-09-16T00:00:00Z INF PID:{os.getpid()}, TID:{os.getpid()}, Comm:test, FD:3, Tuple:[127.0.0.1]:1->[127.0.0.1]:2, Type:WRITE, Len:5',flush=True)\n"
                "print('Data(hex):',flush=True)\n"
                "print('68656c6c6f',flush=True)\n"
                "while not stop: time.sleep(0.02)\n",
                encoding="utf-8",
            )
            upstream.chmod(0o700)
            digest = "sha256:" + hashlib.sha256(upstream.read_bytes()).hexdigest()
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "upstream_path": str(upstream),
                        "upstream_sha256": digest,
                        "upstream_release": "test-v1",
                        "module": "gotls",
                        "mapsize_kib": 1024,
                        "readiness_timeout_seconds": 5,
                        "shutdown_drain_seconds": 0,
                    }
                ),
                encoding="utf-8",
            )
            config.chmod(0o600)
            exe_digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
            cgroup_line = Path(f"/proc/{os.getpid()}/cgroup").read_text(encoding="ascii").strip()
            cgroup = Path("/sys/fs/cgroup") / cgroup_line[3:].lstrip("/")
            process = subprocess.Popen(
                [
                    str(MODULE_PATH),
                    "--config",
                    str(config),
                    "--iorec-probe-protocol",
                    "2",
                    "--target-pid",
                    str(os.getpid()),
                    "--target-executable",
                    str(executable),
                    "--target-executable-sha256",
                    exe_digest,
                    "--filter-scope",
                    "cgroup",
                    "--target-cgroup",
                    str(cgroup),
                    "--run-id",
                    "run-test-gotls",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            assert process.stdout is not None
            # Exercise the scheduling window where both readiness and evidence
            # are available before the parent first reads stdout.
            time.sleep(0.15)
            ready = json.loads(process.stdout.readline())
            self.assertIn("go_tls_plaintext", ready["capabilities"])
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr.decode())
            records = [json.loads(line) for line in stdout.splitlines()]
            self.assertEqual([record["type"] for record in records], ["evidence", "final"])
            self.assertEqual(records[0]["payload_base64"], "aGVsbG8=")
            self.assertTrue(records[1]["complete"])


if __name__ == "__main__":
    unittest.main()
