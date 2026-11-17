"""Persistent registry and administrator authorization tests."""

from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from database.identity_database import connect_database
from security.authentication.auth_service import AuthenticationError
from security.identity.uav_registry import UAVRegistry


class UAVRegistryTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.registry = UAVRegistry(self.path)
        self.auth = self.registry.auth
        self.admin_id = self.auth.bootstrap_admin("admin", "admin-test-password")
        self.token = self.auth.login("admin", "admin-test-password")

    def register(self, **changes):
        values = dict(name="SITL", system_id=1, certificate_identity="urn:sentinel:uav:1",
                      signing_key_id="a" * 64)
        values.update(changes)
        return self.registry.register(self.token, **values)

    def test_pending_registration_survives_restart_with_explicit_mapping(self):
        uav_id = self.register()
        rows = UAVRegistry(self.path).list_uavs(self.token)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["uav_id"], uav_id)
        self.assertEqual(rows[0]["status"], "pending")
        self.assertEqual(rows[0]["certificate_identity"], "urn:sentinel:uav:1")
        self.assertEqual(rows[0]["signing_key_id"], "a" * 64)

    def test_duplicate_and_invalid_registration_are_rejected(self):
        self.register()
        with self.assertRaises(sqlite3.IntegrityError):
            self.register(certificate_identity="urn:sentinel:uav:2")
        with self.assertRaises(sqlite3.IntegrityError):
            self.register(system_id=2)
        with self.assertRaises(ValueError):
            self.register(system_id=256)
        with self.assertRaises(ValueError):
            self.register(signing_key_id="placeholder")
        with self.assertRaises(ValueError):
            self.register(certificate_identity="unknown")

    def test_nonadministrator_and_revoked_session_cannot_manage_registry(self):
        user = self.auth.create_user(self.token, "operator", "other-test-password", "Operator")
        operator = self.auth.login("operator", "other-test-password")
        uav_id = self.register()
        self.registry.set_status(self.token, uav_id, "active")
        with self.assertRaises(AuthenticationError):
            self.registry.assign(operator, user, uav_id)
        with self.assertRaises(AuthenticationError):
            self.registry.register(operator, "other", 2, "urn:sentinel:uav:2", "b" * 64)
        self.auth.logout(self.token)
        with self.assertRaises(AuthenticationError):
            self.registry.set_status(self.token, uav_id, "revoked")

    def test_assignments_are_explicit_idempotent_and_removable(self):
        uav_id = self.register()
        self.registry.set_status(self.token, uav_id, "active")
        self.registry.assign(self.token, self.admin_id, uav_id)
        self.registry.assign(self.token, self.admin_id, uav_id)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM uav_assignments").fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM identity_events WHERE event = 'uav_assigned'"
            ).fetchone()[0], 1)
        self.registry.unassign(self.token, self.admin_id, uav_id)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM uav_assignments").fetchone()[0], 0)

    def test_assignment_requires_active_known_user_and_uav(self):
        uav_id = self.register()
        with self.assertRaises(ValueError):
            self.registry.assign(self.token, self.admin_id, uav_id)
        self.registry.set_status(self.token, uav_id, "active")
        with self.assertRaises(ValueError):
            self.registry.assign(self.token, "missing-user", uav_id)
        user = self.auth.create_user(self.token, "viewer", "other-test-password", "Viewer")
        self.auth.set_user_status(self.token, user, "suspended")
        with self.assertRaises(ValueError):
            self.registry.assign(self.token, user, uav_id)

    def test_revocation_is_terminal_and_audited(self):
        uav_id = self.register()
        self.registry.set_status(self.token, uav_id, "active")
        self.registry.set_status(self.token, uav_id, "suspended")
        self.registry.set_status(self.token, uav_id, "revoked")
        with self.assertRaises(ValueError):
            self.registry.set_status(self.token, uav_id, "active")
        with closing(connect_database(self.path)) as db:
            events = [row[0] for row in db.execute(
                "SELECT reason FROM identity_events WHERE event = 'uav_status_changed' ORDER BY event_id"
            )]
            self.assertEqual(events, ["active", "suspended", "revoked"])
