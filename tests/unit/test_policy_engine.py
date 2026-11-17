"""Resource authorization and immediate policy-state enforcement tests."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from database.identity_database import connect_database
from security.authorization.policy_engine import PolicyEngine
from security.identity.uav_registry import UAVRegistry


class PolicyEngineTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.registry = UAVRegistry(self.path)
        self.auth = self.registry.auth
        self.admin_id = self.auth.bootstrap_admin("admin", "admin-test-password")
        self.admin = self.auth.login("admin", "admin-test-password")
        self.uav = self.registry.register(self.admin, "SITL", 1, "urn:sentinel:uav:1", "a" * 64)
        self.registry.set_status(self.admin, self.uav, "active")
        self.engine = PolicyEngine(self.path)

    def account(self, name, role):
        user_id = self.auth.create_user(self.admin, name, "other-test-password", role)
        token = self.auth.login(name, "other-test-password")
        self.registry.assign(self.admin, user_id, self.uav)
        return user_id, token

    def test_explicit_assignment_applies_to_administrator(self):
        self.assertEqual(self.engine.authorize(self.admin, self.uav, "status.read").reason,
                         "uav_unassigned")
        self.registry.assign(self.admin, self.admin_id, self.uav)
        decision = self.engine.authorize(self.admin, self.uav, "status.read")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.user_id, self.admin_id)

    def test_operator_and_viewer_permissions_and_default_deny(self):
        _, operator = self.account("operator", "Operator")
        _, viewer = self.account("viewer", "Viewer")
        self.assertTrue(self.engine.authorize(operator, self.uav, "command.rtl").allowed)
        self.assertTrue(self.engine.authorize(viewer, self.uav, "telemetry.read").allowed)
        self.assertEqual(self.engine.authorize(viewer, self.uav, "command.rtl").reason, "role_denied")
        self.assertEqual(self.engine.authorize(operator, self.uav, "command.arm").reason,
                         "unsupported_action")

    def test_assignment_and_uav_revocation_apply_to_existing_sessions(self):
        user, token = self.account("operator", "Operator")
        self.registry.unassign(self.admin, user, self.uav)
        self.assertEqual(self.engine.authorize(token, self.uav, "status.read").reason,
                         "uav_unassigned")
        self.registry.assign(self.admin, user, self.uav)
        self.registry.set_status(self.admin, self.uav, "revoked")
        self.assertEqual(self.engine.authorize(token, self.uav, "status.read").reason, "uav_inactive")

    def test_invalid_expired_and_revoked_sessions_are_denied(self):
        user, token = self.account("operator", "Operator")
        self.assertEqual(self.engine.authorize("bad-token", self.uav, "status.read").reason,
                         "invalid_session")
        self.engine.auth.clock = lambda: 10**12
        self.assertEqual(self.engine.authorize(token, self.uav, "status.read").reason, "invalid_session")
        self.engine.auth.clock = self.auth.clock
        self.auth.set_user_status(self.admin, user, "revoked")
        self.assertEqual(self.engine.authorize(token, self.uav, "status.read").reason, "invalid_session")

    def test_current_role_changes_and_unknown_resources(self):
        user, token = self.account("operator", "Operator")
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE users SET role_name = 'Viewer' WHERE user_id = ?", (user,))
        self.assertEqual(self.engine.authorize(token, self.uav, "command.rtl").reason, "role_denied")
        self.assertEqual(self.engine.authorize(token, "missing", "telemetry.read").reason, "unknown_uav")

    def test_decisions_are_durable_and_exclude_session_tokens(self):
        _, token = self.account("operator", "Operator")
        self.engine.authorize(token, self.uav, "status.read")
        PolicyEngine(self.path).authorize(None, self.uav, "status.read")
        with closing(connect_database(self.path)) as db:
            rows = db.execute("SELECT decision, reason FROM authorization_events ORDER BY event_id").fetchall()
            self.assertEqual([tuple(row) for row in rows],
                             [("allow", "allowed"), ("deny", "invalid_session")])
            self.assertNotIn(token, str([tuple(row) for row in db.execute(
                "SELECT * FROM authorization_events")]))
