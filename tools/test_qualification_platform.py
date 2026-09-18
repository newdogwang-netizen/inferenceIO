import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import qualification_platform as platform


class IsolationTests(unittest.TestCase):
    def test_environment_cannot_inherit_development_auth_or_another_database(self):
        with mock.patch.dict(os.environ, {"IOREC_AUTH_MODE": "dev", "DATABASE_URL": "wrong",
                                          "COMPOSE_FILE": "/wrong", "POSTGRES_PASSWORD": "wrong",
                                          "OBJECT_STORE_DIR": "/wrong", "PATH": "/usr/bin"}, clear=True):
            result = platform.environment({"environment": {"IOREC_AUTH_MODE": "token", "POSTGRES_PASSWORD": "private"}})
        self.assertEqual(result["IOREC_AUTH_MODE"], "token")
        self.assertEqual(result["POSTGRES_PASSWORD"], "private")
        self.assertEqual(result["COMPOSE_DISABLE_ENV_FILE"], "1")
        self.assertEqual(result["PATH"], "/usr/bin")
        for key in ("DATABASE_URL", "COMPOSE_FILE", "OBJECT_STORE_DIR"):
            self.assertNotIn(key, result)

    def test_secret_file_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "token"
            platform.private_text(path, "test-only")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                platform.private_text(path, "replacement")
            link = Path(root) / "link"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                platform.private_text(link, "replacement")
            self.assertEqual(path.read_text(), "test-only\n")

    def test_existing_or_nonqualification_project_rejected_before_any_files(self):
        with tempfile.TemporaryDirectory() as root:
            args = type("Args", (), {"project": "iorec-local", "state": Path(root)/"private", "api_port": 48381, "web_port": 48382})()
            with self.assertRaisesRegex(ValueError, "dedicated"):
                platform.initialize(args)
            args.project = "iorec-qual-test"
            with mock.patch("qualification_platform.subprocess.check_output", return_value=b"existing-resource\n") as command:
                with self.assertRaisesRegex(ValueError, "pre-existing"):
                    platform.initialize(args)
                self.assertIn("-a", command.call_args.args[0])
            self.assertFalse(args.state.exists())


if __name__ == "__main__":
    unittest.main()
