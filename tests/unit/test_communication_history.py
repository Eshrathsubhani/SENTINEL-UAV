"""Persistent GCS heartbeat-path observations and authorized status reads."""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from database.connection import connect_database
from database.identity_database import initialize_database
from database.telemetry_repository import timestamp_us
from security.authorization.policy_engine import PolicyEngine
from security.identity.gateway_registry import RegistryGuard

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"
STAMP = "2026-01-01T00:00:00+00:00"
IDENTITY = "urn:sentinel:uav:1"


class CommunicationHistoryTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.now = timestamp_us(STAMP)
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text())
        initialize_database(self.path)
        self.token = "a" * 43
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE uavs SET signing_key_id=?", ("a" * 64,))
            db.execute("INSERT INTO sessions VALUES (?, 'fixture-user', ?, ?, NULL)",
                       (sha256(self.token.encode()).hexdigest(), self.now // 1000000,
                        self.now // 1000000 + 3600))
        self.guard = RegistryGuard(self.path, clock=lambda: self.now)
        self.engine = PolicyEngine(self.path)
        self.engine.auth.clock = lambda: self.now / 1000000

    def record(self, identifier="one", captured=None):
        from datetime import datetime, timezone, timedelta
        stamp = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                 + timedelta(microseconds=self.now if captured is None else captured)).isoformat()
        return {"schema_version": 3, "record_id": identifier, "vehicle_id": "1",
                "uav_identity": IDENTITY, "system_id": 1, "component_id": 1,
                "message_type": "HEARTBEAT", "source_boot_ms": None, "captured_at": stamp,
                "values": {"vehicle_type": 2, "armed": 0}, "signing_key_id": "a" * 64}

    def heartbeat(self, identifier="one", captured=None):
        self.guard(self.record(identifier, captured), IDENTITY)

    def status(self, **kwargs):
        return self.engine.communication_status(self.token, "fixture-uav", **kwargs)

    def events(self):
        with closing(connect_database(self.path)) as db:
            return [row[0] for row in db.execute("SELECT event FROM communication_events ORDER BY event_id")]

    def test_initial_status_is_unknown_despite_legacy_snapshot(self):
        status = self.status()
        self.assertEqual(status["state"], "unknown")
        self.assertEqual(status["events"], [])
        self.assertIsNone(status["last_heartbeat_received_at_us"])

    def test_first_heartbeat_and_subsequent_fresh_heartbeats_log_only_transition(self):
        self.heartbeat()
        self.now += 1000000
        self.heartbeat("two")
        status = self.status()
        self.assertEqual(status["state"], "connected")
        self.assertEqual(status["source"], "gcs_accepted_heartbeat")
        self.assertEqual(status["timeout_s"], 5)
        self.assertEqual(status["heartbeat_age_s"], 0)
        self.assertEqual(self.events(), ["heartbeat_received"])

    def test_timeout_is_detected_once_at_boundary_even_with_listener_stopped(self):
        self.heartbeat()
        self.now += 5000000
        self.assertEqual(self.status()["state"], "lost")
        self.guard.check_heartbeat_timeouts()
        self.status()
        self.assertEqual(self.events(), ["heartbeat_received", "heartbeat_lost"])

    def test_restart_preserves_state_and_detects_gap_before_recovery(self):
        self.heartbeat()
        self.now += 6000000
        self.guard = RegistryGuard(self.path, clock=lambda: self.now)
        self.heartbeat("two")
        self.assertEqual(self.status()["state"], "connected")
        self.assertEqual(self.events(), ["heartbeat_received", "heartbeat_lost", "heartbeat_recovered"])

    def test_duplicate_does_not_refresh_heartbeat_age(self):
        record = self.record()
        self.guard(record, IDENTITY)
        self.now += 4000000
        self.guard(record, IDENTITY)
        self.assertEqual(self.status()["heartbeat_age_s"], 4)
        self.now += 1000000
        self.assertEqual(self.status()["state"], "lost")

    def test_stale_future_and_nonadvancing_captures_do_not_claim_connectivity(self):
        self.heartbeat("stale", self.now - 6000000)
        self.heartbeat("future", self.now + 1000000)
        self.assertEqual(self.status()["state"], "unknown")
        captured = self.now
        self.heartbeat("fresh")
        self.now += 1000000
        self.heartbeat("equal", captured)
        self.assertEqual(self.status()["heartbeat_age_s"], 1)
        self.now += 4000000
        self.assertEqual(self.status()["state"], "lost")

    def test_nonheartbeat_records_do_not_keep_heartbeat_path_connected(self):
        self.heartbeat()
        self.now += 4000000
        battery = dict(self.record("battery"), message_type="SYS_STATUS",
                       values={"battery_remaining_pct": 50, "battery_voltage_v": 12.0})
        self.guard(battery, IDENTITY)
        self.now += 1000000
        self.guard.check_heartbeat_timeouts()
        self.assertEqual(self.status()["state"], "lost")

    def test_removed_assignment_and_revoked_session_cannot_read_events(self):
        self.heartbeat()
        with closing(connect_database(self.path)) as db, db:
            db.execute("DELETE FROM uav_assignments")
        with self.assertRaisesRegex(PermissionError, "uav_unassigned"):
            self.status()
        with closing(connect_database(self.path)) as db, db:
            db.execute("INSERT INTO uav_assignments (user_id,uav_id) VALUES ('fixture-user','fixture-uav')")
            db.execute("UPDATE sessions SET revoked_at_epoch=? WHERE token_hash=?",
                       (self.now // 1000000, sha256(self.token.encode()).hexdigest()))
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.status()

    def test_assigned_viewer_can_read_active_uav_but_not_inactive_one(self):
        self.heartbeat()
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE users SET role_name='Viewer'")
        self.assertEqual(self.status()["state"], "connected")
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE uavs SET status='suspended'")
        with self.assertRaisesRegex(PermissionError, "uav_inactive"):
            self.status()

    def test_clock_rollback_and_changed_registry_key_return_unknown(self):
        self.heartbeat()
        self.now -= 1000000
        self.assertEqual(self.status()["reason"], "clock_moved_backwards")
        self.now += 2000000
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE uavs SET signing_key_id=?", ("b" * 64,))
        self.assertEqual(self.status()["state"], "unknown")
        self.assertEqual(self.status()["reason"], "registry_credentials_changed")

    def test_equal_time_transitions_page_stably_with_numeric_event_ids(self):
        self.heartbeat()
        self.now += 6000000
        self.heartbeat("two")
        first = self.status(limit=1)
        second = self.status(limit=1, before=first["next_before"])
        third = self.status(limit=1, before=second["next_before"])
        self.assertEqual([first["events"][0]["event"], second["events"][0]["event"],
                          third["events"][0]["event"]],
                         ["heartbeat_recovered", "heartbeat_lost", "heartbeat_received"])
        self.assertIsNone(third["next_before"])

    def test_communication_write_failure_rolls_back_entire_heartbeat_acceptance(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("CREATE TRIGGER fail_communication BEFORE INSERT ON communication_events "
                       "BEGIN SELECT RAISE(ABORT,'injected event failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.heartbeat()
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM communication_state").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT payload_json FROM telemetry_snapshots").fetchone()[0], "{}")

    def test_invalid_page_and_timeout_configuration_are_rejected(self):
        for options in ({"limit": True}, {"limit": 0}, {"limit": 1001}, {"before": [1, "x"]}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.status(**options)
        for timeout in (False, 0, -1, float("nan"), 3601):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                RegistryGuard(self.path, heartbeat_timeout=timeout)

    def test_wrong_registry_credential_cannot_create_communication_state(self):
        record = self.record()
        record["signing_key_id"] = "b" * 64
        with self.assertRaises(ValueError):
            self.guard(record, IDENTITY)
        self.assertEqual(self.status()["state"], "unknown")
        self.assertEqual(self.events(), [])

    def test_schema_six_upgrade_preserves_history_without_backfilling_connectivity(self):
        self.heartbeat()
        with closing(connect_database(self.path)) as db, db:
            before = tuple(db.execute("SELECT * FROM telemetry_records").fetchone())
            for trigger in db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'security_project_%'").fetchall():
                db.execute('DROP TRIGGER "' + trigger[0] + '"')
            db.execute("DROP TABLE security_events")
            db.execute("DROP TABLE communication_events")
            db.execute("DROP TABLE communication_state")
            db.execute("PRAGMA user_version=6")
        initialize_database(self.path)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(tuple(db.execute("SELECT * FROM telemetry_records").fetchone()), before)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 8)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(self.status()["state"], "unknown")

    def test_failed_schema_seven_migration_rolls_back_both_new_tables(self):
        from database import migrations
        from unittest.mock import patch
        with closing(connect_database(self.path)) as db, db:
            for trigger in db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'security_project_%'").fetchall():
                db.execute('DROP TRIGGER "' + trigger[0] + '"')
            db.execute("DROP TABLE security_events")
            db.execute("DROP TABLE communication_events")
            db.execute("DROP TABLE communication_state")
            db.execute("PRAGMA user_version=6")
        original = migrations.version_7

        def failure(db):
            original(db)
            raise RuntimeError("injected after communication tables")

        with patch.object(migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:6], failure)):
            with self.assertRaises(RuntimeError):
                initialize_database(self.path)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 6)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'communication_%'").fetchone()[0], 0)
        initialize_database(self.path)
