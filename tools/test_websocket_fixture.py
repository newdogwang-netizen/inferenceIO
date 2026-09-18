import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import websocket_fixture as fixture


class WebSocketFixtureTests(unittest.TestCase):
    def test_response_bounds_unicode_tools_and_usage(self):
        first = fixture.expected_response({"type": "response.create", "event_id": "q-1", "metadata": {"fixture_index": 0}})
        self.assertEqual(first["usage"]["input_tokens"], 100)
        self.assertEqual(len(first["output"]), 2)
        self.assertIn("中文🙂", first["output"][0]["content"][0]["text"])
        with self.assertRaises(ValueError):
            fixture.expected_response({"type": "response.create", "event_id": "q-1", "metadata": {"fixture_index": 1000}})

    def test_frame_lengths_and_control_bounds(self):
        self.assertEqual(fixture.frame(b"abc"), b"\x81\x03abc")
        self.assertEqual(fixture.frame(b"x"*126)[:4], b"\x81\x7e\x00\x7e")
        with self.assertRaises(ValueError):
            fixture.frame(b"x"*126, 9)

    @unittest.skipUnless(shutil.which("node"), "Node 22+ required for real WebSocket client")
    def test_real_client_fragmentation_unicode_ping_reconnect_and_tool_roundtrip(self):
        server = fixture.Server()
        try:
            script = Path(__file__).with_name("websocket_soak_client.mjs")
            result = subprocess.run(["node", str(script), "--duration-seconds", "1", "--interval-seconds", "0.03", "--calls-per-connection", "3"],
                                    env=dict(os.environ, IOREC_PROXY_URL=server.url), capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stderr[:500])
            report = json.loads(result.stdout)
            self.assertEqual(report["errors"], 0)
            self.assertGreater(report["successes"], 13)
            self.assertLessEqual(report["successes"], 34)
            self.assertGreater(report["transport_attempts"], 1)
            self.assertGreaterEqual(report["measurement_seconds"], 1)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
