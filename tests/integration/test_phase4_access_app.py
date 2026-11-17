"""Exercise authentication and administration through the Streamlit entry point."""

from contextlib import closing
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from database.identity_database import connect_database
from security.authentication.auth_service import AuthService

APP = Path(__file__).resolve().parents[2] / "phase4_access_app.py"


class Phase4AccessAppTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.auth = AuthService(self.path)
        self.auth.bootstrap_admin("admin", "admin-test-password")
        self.admin = self.auth.login("admin", "admin-test-password")
        environment = patch.dict(os.environ, {"SENTINEL_IDENTITY_DB": str(self.path)})
        environment.start()
        self.addCleanup(environment.stop)

    def login(self, username, password):
        app = AppTest.from_file(str(APP), default_timeout=20).run()
        self.assertFalse(app.exception)
        app.text_input(key="username").set_value(username)
        app.text_input(key="password").set_value(password)
        next(button for button in app.button if button.label == "Sign in").click().run()
        self.assertFalse(app.exception)
        return app

    def test_administrator_creates_operator_through_console_then_logs_out(self):
        app = self.login("admin", "admin-test-password")
        app.sidebar.radio[0].set_value("Users").run()
        app.text_input(key="new_username").set_value("console_operator")
        app.text_input(key="new_password").set_value("console-test-password")
        next(button for button in app.button if button.label == "Create user").click().run()
        self.assertFalse(app.exception)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT role_name FROM users WHERE username='console_operator'"
            ).fetchone()[0], "Operator")
        next(button for button in app.button if button.label == "Sign out").click().run()
        self.assertTrue(any(button.label == "Sign in" for button in app.button))

    def test_viewer_has_no_management_controls_and_revocation_ends_ui_session(self):
        viewer_id = self.auth.create_user(self.admin, "viewer", "viewer-test-password", "Viewer")
        app = self.login("viewer", "viewer-test-password")
        self.assertEqual(list(app.sidebar.radio[0].options), ["Telemetry"])
        self.assertFalse(any(button.label == "Request simulator status" for button in app.button))
        self.auth.set_user_status(self.admin, viewer_id, "revoked")
        app.run()
        self.assertFalse(app.exception)
        self.assertTrue(any(button.label == "Sign in" for button in app.button))
