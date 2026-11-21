"""History retention, authorization, pagination, deduplication and atomic writes."""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest

from database.connection import connect_database
from database.identity_database import initialize_database
from security.authorization.policy_engine import PolicyEngine
from security.identity.gateway_registry import RegistryGuard

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"
START = "2026-01-01T00:00:00+00:00"
END = "2026-01-02T00:00:00+00:00"
IDENTITY = "urn:sentinel:uav:1"


class TelemetryHistoryTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text())
        initialize_database(self.path)
        self.token = "a" * 43
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE uavs SET signing_key_id=?", ("a" * 64,))
            db.execute("INSERT INTO sessions VALUES (?, 'fixture-user', ?, ?, NULL)",
                       (sha256(self.token.encode()).hexdigest(), int(time.time()), int(time.time()) + 3600))
        self.guard = RegistryGuard(self.path)
        self.engine = PolicyEngine(self.path)

    def record(self, identifier="one", captured=START, armed=0):
        return {"schema_version": 3, "record_id": identifier, "vehicle_id": "1",
                "uav_identity": IDENTITY, "system_id": 1, "component_id": 1,
                "message_type": "HEARTBEAT", "source_boot_ms": None, "captured_at": captured,
                "values": {"vehicle_type": 2, "armed": armed}, "signing_key_id": "a" * 64}

    def read(self, **kwargs):
        return self.engine.read_history(self.token, "fixture-uav", START, END, **kwargs)

    def test_records_survive_restart_and_latest_snapshot_remains_one(self):
        self.guard(self.record("one"), IDENTITY)
        self.guard(self.record("two"), IDENTITY)
        result = PolicyEngine(self.path).read_history(self.token, "fixture-uav", START, END)
        self.assertEqual([r["record"]["record_id"] for r in result["telemetry"]], ["one", "two"])
        self.assertEqual(result["telemetry"][0]["source"], "authenticated_uav_gateway")
        self.assertEqual(result["telemetry"][0]["validation_status"], "gateway_attested")
        self.assertEqual(len(self.engine.read_telemetry(self.token, "fixture-uav")), 1)

    def test_duplicate_is_idempotent_but_changed_content_is_rejected_and_audited(self):
        self.guard(self.record(), IDENTITY)
        self.guard(dict(reversed(list(self.record().items()))), IDENTITY)
        with self.assertRaises(ValueError):
            self.guard(self.record(armed=1), IDENTITY)
        self.assertEqual(len(self.read()["telemetry"]), 1)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT reason FROM authorization_events ORDER BY event_id DESC LIMIT 1").fetchone()[0], "allowed")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM authorization_events WHERE reason='record_id_conflict'").fetchone()[0], 1)
            self.assertEqual(json.loads(db.execute("SELECT payload_json FROM telemetry_snapshots").fetchone()[0])["values"]["armed"], 0)

    def test_old_history_record_does_not_replace_newer_snapshot(self):
        self.guard(self.record("new", "2026-01-01T12:00:00+00:00"), IDENTITY)
        self.guard(self.record("old"), IDENTITY)
        self.assertEqual(len(self.read()["telemetry"]), 2)
        latest = self.engine.read_telemetry(self.token, "fixture-uav")
        self.assertEqual(latest[0]["record"]["record_id"], "new")

    def test_time_range_is_half_open_and_pages_have_no_gaps_at_equal_timestamps(self):
        for identifier in ("c", "a", "b"):
            self.guard(self.record(identifier), IDENTITY)
        self.guard(self.record("end", END), IDENTITY)
        first = self.read(limit=2)
        second = self.read(limit=2, cursor=first["next_cursor"])
        self.assertEqual([r["record"]["record_id"] for r in first["telemetry"]], ["a", "b"])
        self.assertEqual([r["record"]["record_id"] for r in second["telemetry"]], ["c"])
        self.assertIsNone(second["next_cursor"])

    def test_authorization_is_rechecked_after_assignment_or_account_change(self):
        self.guard(self.record(), IDENTITY)
        with closing(connect_database(self.path)) as db, db:
            db.execute("DELETE FROM uav_assignments")
        with self.assertRaisesRegex(PermissionError, "uav_unassigned"):
            self.read()
        with closing(connect_database(self.path)) as db, db:
            db.execute("INSERT INTO uav_assignments (user_id,uav_id) VALUES ('fixture-user','fixture-uav')")
            db.execute("UPDATE users SET status='revoked'")
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.read()

    def test_viewer_can_only_read_assigned_active_uav_history(self):
        self.guard(self.record(), IDENTITY)
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE users SET role_name='Viewer'")
        self.assertEqual(len(self.read()["telemetry"]), 1)
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE uavs SET status='suspended'")
        with self.assertRaisesRegex(PermissionError, "uav_inactive"):
            self.read()

    def test_storage_failure_rolls_back_history_snapshot_and_acceptance(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("CREATE TRIGGER fail_snapshot BEFORE UPDATE ON telemetry_snapshots BEGIN SELECT RAISE(ABORT,'injected'); END")
            before = db.execute("SELECT COUNT(*) FROM authorization_events").fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.guard(self.record(), IDENTITY)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM authorization_events").fetchone()[0], before)
            self.assertEqual(db.execute("SELECT payload_json FROM telemetry_snapshots").fetchone()[0], "{}")

    def test_invalid_record_and_invalid_query_inputs_do_not_enter_history(self):
        with self.assertRaises(ValueError):
            self.guard(dict(self.record(), values={"armed": 0}), IDENTITY)
        for options in ({"limit": 0}, {"limit": True}, {"cursor": "invalid"}, {"limit": 1001}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.read(**options)
        with self.assertRaises(ValueError):
            self.engine.read_history(self.token, "fixture-uav", "2026-01-01", END)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0)

    def test_unknown_uav_query_is_denied_and_cannot_inject_sql(self):
        with self.assertRaisesRegex(PermissionError, "unknown_uav"):
            self.engine.read_history(self.token, "fixture-uav' OR 1=1 --", START, END)

    def test_version4_migration_does_not_invent_historical_records(self):
        self.assertEqual(self.read()["telemetry"], [])
        self.assertEqual(len(self.engine.read_telemetry(self.token, "fixture-uav")), 1)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 7)
