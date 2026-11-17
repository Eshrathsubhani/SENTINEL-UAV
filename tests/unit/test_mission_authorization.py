"""Evaluate mission permissions against fresh, identity-bound GPS telemetry."""

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from database.identity_database import connect_database
from security.authorization.policy_engine import PolicyEngine
from security.identity.gateway_registry import RegistryGuard
from security.identity.uav_registry import UAVRegistry


class MissionAuthorizationTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.registry = UAVRegistry(self.path)
        self.auth = self.registry.auth
        self.user = self.auth.bootstrap_admin("admin", "admin-test-password")
        self.token = self.auth.login("admin", "admin-test-password")
        self.uav = self.registry.register(self.token, "SITL", 1, "urn:sentinel:uav:1", "a" * 64)
        self.registry.set_status(self.token, self.uav, "active")
        self.registry.assign(self.token, self.user, self.uav)
        self.engine = PolicyEngine(self.path)
        self.now = float(int(self.auth.clock()))
        self.engine.auth.clock = lambda: self.now

    def configure(self):
        self.engine.configure_mission(self.token, self.uav, -35.3632622, 149.1652375)

    def position(self, *, age=0, latitude=-35.3632622, captured_at=None, key="a" * 64):
        stamp = datetime.fromtimestamp(self.now - age, timezone.utc).isoformat()
        record = {
            "schema_version": 3, "message_type": "GLOBAL_POSITION_INT",
            "system_id": 1, "uav_identity": "urn:sentinel:uav:1",
            "signing_key_id": "a" * 64, "captured_at": stamp,
            "values": {"latitude_deg": latitude, "longitude_deg": 149.1652375},
        }
        RegistryGuard(self.path)(record, "urn:sentinel:uav:1")
        record["signing_key_id"] = key
        record["captured_at"] = captured_at or stamp
        import json
        with closing(connect_database(self.path)) as db, db:
            db.execute(
                "UPDATE telemetry_snapshots SET received_at_utc=?, payload_json=? WHERE uav_id=?",
                (stamp, json.dumps(record), self.uav),
            )

    def reason(self):
        return self.engine.authorize(self.token, self.uav, "mission.update").reason

    def test_missing_policy_and_missing_position_are_denied(self):
        self.assertEqual(self.reason(), "mission_policy_missing")
        self.configure()
        self.assertEqual(self.reason(), "mission_missing_position")

    def test_fresh_inside_position_is_allowed_and_audited(self):
        self.configure()
        self.position(age=1)
        self.assertEqual(self.reason(), "allowed")
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT decision FROM authorization_events WHERE action='mission.update'"
            ).fetchone()[0], "allow")

    def test_stale_future_outside_and_invalid_positions_are_denied(self):
        self.configure()
        self.position(age=3)
        self.assertEqual(self.reason(), "mission_stale_position")
        self.position(age=-1)
        self.assertEqual(self.reason(), "mission_future_position")
        self.position(latitude=-35.361)
        self.assertEqual(self.reason(), "mission_outside_area")
        self.position(captured_at="invalid")
        self.assertEqual(self.reason(), "mission_invalid_position")
        self.position(key="b" * 64)
        self.assertEqual(self.reason(), "mission_identity_mismatch")

    def test_viewer_cannot_update_or_configure_and_unassigned_admin_is_denied(self):
        viewer_id = self.auth.create_user(self.token, "viewer", "viewer-test-password", "Viewer")
        viewer = self.auth.login("viewer", "viewer-test-password")
        self.registry.assign(self.token, viewer_id, self.uav)
        self.assertEqual(self.engine.authorize(viewer, self.uav, "mission.update").reason, "role_denied")
        with self.assertRaises(PermissionError):
            self.engine.configure_mission(viewer, self.uav, 0, 0)
        self.registry.unassign(self.token, self.user, self.uav)
        self.assertEqual(self.reason(), "uav_unassigned")

    def test_policy_change_applies_to_existing_session(self):
        self.configure()
        self.position()
        self.assertEqual(self.reason(), "allowed")
        self.engine.configure_mission(self.token, self.uav, -35.361, 149.1652375)
        self.assertEqual(self.reason(), "mission_outside_area")
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT version FROM policies").fetchone()[0], 2)

    def test_malformed_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.configure_mission(self.token, self.uav, 91, 0)
        with self.assertRaises(ValueError):
            self.engine.configure_mission(self.token, self.uav, True, 0)
