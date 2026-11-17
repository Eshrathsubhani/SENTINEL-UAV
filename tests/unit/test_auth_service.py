"""Authentication regression checks against a temporary persistent database."""

from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from database.identity_database import connect_database, initialize_database
from security.authentication.auth_service import AuthenticationError, AuthService, SESSION_SECONDS


class AuthServiceTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.now = 1000000
        self.service = AuthService(self.path, clock=lambda: self.now)
        self.admin_id = self.service.bootstrap_admin("admin", "admin-test-password")
        self.admin = self.service.login("admin", "admin-test-password")

    def test_password_and_session_secrets_are_not_stored(self):
        self.assertEqual(self.service.authenticate(self.admin)["user_id"], self.admin_id)
        with closing(connect_database(self.path)) as db:
            password_hash = db.execute("SELECT password_hash FROM users").fetchone()[0]
            self.assertTrue(password_hash.startswith("$argon2id$"))
            self.assertNotEqual(password_hash, "admin-test-password")
            token_hash = db.execute("SELECT token_hash FROM sessions").fetchone()[0]
            self.assertNotEqual(token_hash, self.admin)
            self.assertNotIn(self.admin, self.path.read_bytes().decode("latin1"))
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_login_for_all_roles_and_administrator_creation_boundary(self):
        for role in ("Operator", "Viewer"):
            with self.subTest(role=role):
                name = role.lower()
                self.service.create_user(self.admin, name, "other-test-password", role)
                token = self.service.login(name.upper(), "other-test-password")
                self.assertEqual(self.service.authenticate(token)["role_name"], role)
                with self.assertRaises(AuthenticationError):
                    self.service.create_user(token, "intruder", "other-test-password", "Administrator")
        with self.assertRaises(AuthenticationError):
            self.service.bootstrap_admin("another", "another-test-password")

    def test_expiration_and_logout_survive_restart(self):
        restarted = AuthService(self.path, clock=lambda: self.now)
        restarted.authenticate(self.admin)
        self.service.logout(self.admin)
        self.service.logout(self.admin)
        with self.assertRaises(AuthenticationError):
            restarted.authenticate(self.admin)
        token = self.service.login("admin", "admin-test-password")
        self.now += SESSION_SECONDS
        with self.assertRaises(AuthenticationError):
            restarted.authenticate(token)

    def test_failed_login_throttle_persists_and_expires(self):
        for _ in range(5):
            with self.assertRaises(AuthenticationError):
                self.service.login("admin", "incorrect")
        restarted = AuthService(self.path, clock=lambda: self.now)
        with self.assertRaises(AuthenticationError):
            restarted.login("admin", "admin-test-password")
        self.now += 60
        restarted.authenticate(restarted.login("admin", "admin-test-password"))
        with self.assertRaises(AuthenticationError):
            self.service.login("unknown", "incorrect")

    def test_suspension_and_revocation_invalidate_existing_sessions(self):
        user = self.service.create_user(self.admin, "operator", "other-test-password", "Operator")
        token = self.service.login("operator", "other-test-password")
        self.service.set_user_status(self.admin, user, "suspended")
        with self.assertRaises(AuthenticationError):
            self.service.authenticate(token)
        with self.assertRaises(AuthenticationError):
            self.service.login("operator", "other-test-password")
        self.service.set_user_status(self.admin, user, "active")
        with self.assertRaises(AuthenticationError):
            self.service.authenticate(token)
        token = self.service.login("operator", "other-test-password")
        self.service.set_user_status(self.admin, user, "revoked")
        with self.assertRaises(AuthenticationError):
            self.service.authenticate(token)
        with self.assertRaises(ValueError):
            self.service.set_user_status(self.admin, user, "active")

    def test_schema_one_upgrade_preserves_existing_users(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("DROP TABLE login_attempts")
            db.execute("PRAGMA user_version = 1")
        initialize_database(self.path)
        self.assertEqual(self.service.authenticate(self.admin)["username"], "admin")

    def test_duplicate_and_malformed_registration_and_audit(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.create_user(self.admin, "ADMIN", "another-test-password", "Viewer")
        with self.assertRaises(ValueError):
            self.service.create_user(self.admin, "bad name", "another-test-password", "Viewer")
        with self.assertRaises(ValueError):
            self.service.create_user(self.admin, "valid", "short", "Viewer")
        with closing(connect_database(self.path)) as db:
            events = {row[0] for row in db.execute("SELECT event FROM identity_events")}
            self.assertTrue({"administrator_initialized", "login_succeeded"} <= events)
