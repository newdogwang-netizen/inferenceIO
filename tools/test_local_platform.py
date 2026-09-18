import unittest
from unittest import mock

import local_platform as platform


class LocalPlatformTests(unittest.TestCase):
    @mock.patch.object(platform, "api_request")
    def test_no_worker_is_not_healthy(self, request):
        request.side_effect = [{"ok": True}, {"ok": True}, platform.Failure("platform_http_503")]
        result = platform.status()
        self.assertFalse(result["ok"])
        self.assertFalse(result["workers"]["ok"])
        self.assertEqual(result["web_url"], "http://127.0.0.1:8088")

    @mock.patch.object(platform, "api_request")
    def test_error_message_does_not_echo_credentials(self, request):
        request.side_effect = RuntimeError("password=secret")
        self.assertNotIn("secret", str(platform.status()))

    def test_environment_extraction_is_not_returned_as_status(self):
        self.assertEqual(platform.container_env(None), {})
        self.assertEqual(platform.container_env({"Config": {"Env": ["FOO=a=b"]}}), {"FOO": "a=b"})


if __name__ == "__main__":
    unittest.main()
