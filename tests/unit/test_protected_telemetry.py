"""Verify stored telemetry is scoped to current backend permissions."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from database.identity_database import connect_database, initialize_database
from security.authorization.policy_engine import PolicyEngine
from security.identity.gateway_registry import RegistryGuard
from security.identity.uav_registry import UAVRegistry


class ProtectedTelemetryTest(unittest.TestCase):
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
        self.registry.assign(self.admin, self.admin_id, self.uav)
        self.engine = PolicyEngine(self.path)
        self.guard = RegistryGuard(self.path)
        self.record = {
            "schema_version": 3, "uav_identity": "urn:sentinel:uav:1",
            "system_id": 1, "signing_key_id": "a" * 64,
            "message_type": "HEARTBEAT", "record_id": "first",
            "vehicle_id": "1", "component_id": 1, "source_boot_ms": None,
            "captured_at": "2026-01-01T00:00:00+00:00",
            "values": {"vehicle_type": 2, "armed": 0},
        }

    def test_only_latest_accepted_record_is_returned_and_survives_restart(self):
        self.guard(self.record, "urn:sentinel:uav:1")
        updated = dict(self.record, record_id="second")
        self.guard(updated, "urn:sentinel:uav:1")
        records = PolicyEngine(self.path).read_telemetry(self.admin, self.uav)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["record"], updated)
        self.assertIn("+00:00", records[0]["received_at_utc"])

    def test_unassigned_viewer_denied_then_assigned_viewer_allowed(self):
        viewer = self.auth.create_user(self.admin, "viewer", "viewer-test-password", "Viewer")
        token = self.auth.login("viewer", "viewer-test-password")
        self.guard(self.record, "urn:sentinel:uav:1")
        with self.assertRaisesRegex(PermissionError, "uav_unassigned"):
            self.engine.read_telemetry(token, self.uav)
        self.registry.assign(self.admin, viewer, self.uav)
        self.assertEqual(len(self.engine.read_telemetry(token, self.uav)), 1)
        self.registry.unassign(self.admin, viewer, self.uav)
        with self.assertRaises(PermissionError):
            self.engine.read_telemetry(token, self.uav)

    def test_inactive_uav_and_revoked_user_lose_access(self):
        self.guard(self.record, "urn:sentinel:uav:1")
        self.registry.set_status(self.admin, self.uav, "suspended")
        with self.assertRaisesRegex(PermissionError, "uav_inactive"):
            self.engine.read_telemetry(self.admin, self.uav)
        self.registry.set_status(self.admin, self.uav, "active")
        self.auth.set_user_status(self.admin, self.admin_id, "revoked")
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.engine.read_telemetry(self.admin, self.uav)

    def test_rejected_ingestion_preserves_last_accepted_snapshot(self):
        self.guard(self.record, "urn:sentinel:uav:1")
        with self.assertRaises(ValueError):
            self.guard(dict(self.record, signing_key_id="b" * 64), "urn:sentinel:uav:1")
        records = self.engine.read_telemetry(self.admin, self.uav)
        self.assertEqual(records[0]["record"]["record_id"], "first")
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM authorization_events WHERE decision = 'deny'"
            ).fetchone()[0], 1)

    def test_schema_two_upgrade_preserves_identity_and_assignments(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("DROP TABLE communication_events")
            db.execute("DROP TABLE communication_state")
            db.execute("DROP TABLE telemetry_records")
            db.execute("DROP TABLE command_requests")
            db.execute("DROP TABLE telemetry_snapshots")
            db.execute("PRAGMA user_version = 2")
        initialize_database(self.path)
        self.assertEqual(self.engine.read_telemetry(self.admin, self.uav), [])
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 7)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM uav_assignments").fetchone()[0], 1)
