"""Backend administration authorization, revocation, and audit scoping."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.administration.access_service import AccessAdministration
from database.identity_database import connect_database
from security.authentication.auth_service import AuthenticationError
from security.identity.uav_registry import UAVRegistry


class AccessAdministrationTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.registry = UAVRegistry(self.path)
        self.auth = self.registry.auth
        self.admin_id = self.auth.bootstrap_admin("admin", "admin-test-password")
        self.admin = self.auth.login("admin", "admin-test-password")
        self.service = AccessAdministration(self.path)
        self.user = self.auth.create_user(self.admin, "operator", "other-test-password", "Operator")
        self.operator = self.auth.login("operator", "other-test-password")

    def test_role_change_invalidates_all_existing_sessions_and_is_audited(self):
        another = self.auth.login("operator", "other-test-password")
        self.service.set_role(self.admin, self.user, "Viewer")
        for token in (self.operator, another):
            with self.assertRaises(AuthenticationError):
                self.auth.authenticate(token)
        token = self.auth.login("operator", "other-test-password")
        self.assertEqual(self.auth.authenticate(token)["role_name"], "Viewer")
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT reason FROM identity_events WHERE event='role_changed'"
            ).fetchone()[0], "Viewer")

    def test_nonadministrator_management_denial_is_persistent(self):
        with self.assertRaises(AuthenticationError):
            self.service.set_role(self.operator, self.user, "Administrator")
        with self.assertRaises(AuthenticationError):
            self.auth.create_user(self.operator, "intruder", "other-test-password", "Administrator")
        with self.assertRaises(AuthenticationError):
            self.registry.list_uavs(self.operator)
        with closing(connect_database(self.path)) as db:
            rows = db.execute(
                "SELECT action FROM authorization_events WHERE actor_id=? AND decision='deny'",
                (self.user,),
            ).fetchall()
            self.assertEqual({row[0] for row in rows}, {"user.set_role", "user.create", "uav.manage"})

    def test_user_listing_excludes_passwords_and_sessions(self):
        rows = self.service.list_users(self.admin)
        self.assertEqual({row["username"] for row in rows}, {"admin", "operator"})
        for row in rows:
            self.assertEqual(set(row), {"user_id", "username", "role_name", "status", "created_at"})
        self.assertNotIn(self.admin, str(rows))

    def test_operator_can_only_view_own_audit_events(self):
        events = self.service.audit_events(self.operator)
        self.assertTrue(events["identity_events"])
        for rows in events.values():
            self.assertTrue(all(row["actor_id"] == self.user for row in rows))
        all_events = self.service.audit_events(self.admin)
        self.assertTrue(any(row["actor_id"] == self.admin_id for row in all_events["identity_events"]))

    def test_viewer_audit_denial_is_recorded(self):
        self.service.set_role(self.admin, self.user, "Viewer")
        viewer = self.auth.login("operator", "other-test-password")
        with self.assertRaises(PermissionError):
            self.service.audit_events(viewer)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT reason FROM authorization_events WHERE actor_id=? AND action='audit.read'",
                (self.user,),
            ).fetchone()[0], "role_denied")

    def test_only_assigned_active_uavs_are_listed(self):
        uav = self.registry.register(self.admin, "SITL", 1, "urn:sentinel:uav:1", "a" * 64)
        self.registry.set_status(self.admin, uav, "active")
        self.assertEqual(self.service.assigned_uavs(self.operator), [])
        self.registry.assign(self.admin, self.user, uav)
        self.assertEqual(self.service.assigned_uavs(self.operator)[0]["uav_id"], uav)
        self.assertEqual(len(self.service.list_assignments(self.admin)), 1)
        self.registry.set_status(self.admin, uav, "suspended")
        self.assertEqual(self.service.assigned_uavs(self.operator), [])
