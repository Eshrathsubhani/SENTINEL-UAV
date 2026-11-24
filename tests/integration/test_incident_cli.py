"""Password-authenticated CLI persistence and role rejection with real SQLite."""

from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.incidents import incident_service
from security.authentication.auth_service import AuthService


class IncidentCLITest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.auth = AuthService(self.path)
        self.password = "Test-only password 123"
        self.auth.bootstrap_admin("admin", self.password)

    def invoke(self, arguments, *, username="admin"):
        output = StringIO()
        args = [
            "incident_service",
            "--database",
            str(self.path),
            "--username",
            username,
            *arguments,
        ]
        with (
            patch("sys.argv", args),
            patch.object(incident_service, "getpass", return_value=self.password),
            redirect_stdout(output),
        ):
            result = incident_service.main()
        self.assertEqual(result, 0)
        self.assertNotIn(self.password, output.getvalue())
        return json.loads(output.getvalue())

    def test_cli_create_note_resolve_and_history_persist_between_service_instances(
        self,
    ):
        case = self.invoke(
            [
                "create",
                "--title",
                "Functional test case",
                "--attack-type",
                "other",
                "--severity",
                "info",
            ]
        )
        identity = case["incident_id"]
        self.invoke(["investigate", "--incident-id", identity])
        self.invoke(
            [
                "note",
                "--incident-id",
                identity,
                "--body",
                "Manual storage verification; no actual attack.",
            ]
        )
        closed = self.invoke(
            [
                "resolve",
                "--incident-id",
                identity,
                "--resolution",
                "Functional test completed.",
            ]
        )
        self.assertEqual(closed["status"], "resolved")
        self.assertEqual(
            self.invoke(["get", "--incident-id", identity])["note_count"], 1
        )
        self.assertEqual(
            len(self.invoke(["history", "--incident-id", identity])["history"]), 4
        )

    def test_cli_viewer_is_rejected_without_traceback_or_password_disclosure(self):
        token = self.auth.login("admin", self.password)
        self.auth.create_user(token, "viewer", self.password, "Viewer")
        self.auth.logout(token)
        error = StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit) as stopped:
            self.invoke(["list"], username="viewer")
        self.assertEqual(stopped.exception.code, 1)
        self.assertIn("role_denied", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())
        self.assertNotIn(self.password, error.getvalue())
