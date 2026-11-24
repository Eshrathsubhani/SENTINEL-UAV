"""Mission lifecycle, authorization, telemetry relationships and migration safety."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.missions.mission_service import MissionService
from database import migrations
from database.connection import database_transaction
from database.identity_database import initialize_database
from security.authentication.auth_service import _token_hash
from security.identity.gateway_registry import RegistryGuard

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"
UAV = "fixture-uav"
IDENTITY = "urn:sentinel:uav:1"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class MissionHistoryTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text(encoding="utf-8"))
        initialize_database(self.path)
        self.now = 1790000000000000
        self.service = MissionService(self.path, clock=lambda: self.now)
        self.token = "A" * 43
        with database_transaction(self.path) as db:
            db.execute("UPDATE uavs SET signing_key_id=?", ("a" * 64,))
            db.execute(
                "INSERT INTO sessions VALUES (?,'fixture-user',0,2000000000,NULL)",
                (_token_hash(self.token),),
            )
        self.guard = RegistryGuard(self.path, clock=lambda: self.now)

    def create(self, name="Patrol", token=None):
        return self.service.create(
            token or self.token,
            UAV,
            name,
            description="Local SITL research mission",
            details={"objective": "stationary trial"},
        )

    def user(self, role, letter, *, assigned=True):
        token, actor = letter * 43, "user-" + letter
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO users(user_id,username,password_hash,role_name) VALUES (?,?,?,?)",
                (actor, actor, "$argon2id$fixture", role),
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,?,0,2000000000,NULL)",
                (_token_hash(token), actor),
            )
            if assigned:
                db.execute(
                    "INSERT INTO uav_assignments(user_id,uav_id) VALUES (?,?)",
                    (actor, UAV),
                )
        return token, actor

    def transition(self, mission, operation):
        self.now += 1000
        return self.service.transition(
            self.token, UAV, mission["mission_id"], operation
        )

    def record(self, record_id="sample", *, captured=None, key=None):
        stamp = (
            EPOCH + timedelta(microseconds=self.now if captured is None else captured)
        ).isoformat()
        return {
            "schema_version": 3,
            "record_id": record_id,
            "vehicle_id": "1",
            "uav_identity": IDENTITY,
            "system_id": 1,
            "component_id": 1,
            "message_type": "HEARTBEAT",
            "source_boot_ms": None,
            "captured_at": stamp,
            "values": {"vehicle_type": 2, "armed": 0},
            "signing_key_id": key or "a" * 64,
        }

    def linked(self, mission, **filters):
        return self.service.telemetry(
            self.token,
            UAV,
            mission["mission_id"],
            "1970-01-01T00:00:00Z",
            "9999-01-01T00:00:00Z",
            **filters,
        )

    def test_create_start_complete_survives_restart_with_history_and_actor(self):
        mission = self.create()
        self.assertEqual(mission["status"], "planned")
        self.assertIsNone(mission["started_at_us"])
        started = self.transition(mission, "start")
        self.now += 1000
        self.guard(self.record(), IDENTITY)
        completed = self.transition(mission, "complete")
        self.assertEqual(completed["started_at_us"], started["started_at_us"])
        self.assertGreater(completed["ended_at_us"], started["started_at_us"])
        restarted = MissionService(self.path, clock=lambda: self.now)
        result = restarted.get(self.token, UAV, mission["mission_id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["telemetry_count"], 1)
        self.assertEqual(
            [e["event"] for e in result["history"]], ["created", "started", "completed"]
        )
        self.assertTrue(all(e["actor_id"] == "fixture-user" for e in result["history"]))
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM security_events WHERE category='mission'"
                ).fetchone()[0],
                3,
            )

    def test_cancel_planned_and_abort_active(self):
        cancelled = self.transition(self.create("Cancelled"), "cancel")
        self.assertIsNone(cancelled["started_at_us"])
        self.assertIsNotNone(cancelled["ended_at_us"])
        mission = self.create("Aborted")
        self.transition(mission, "start")
        self.assertEqual(self.transition(mission, "abort")["status"], "aborted")

    def test_invalid_transitions_are_denied_and_audited(self):
        mission = self.create()
        for operation in ("complete", "abort"):
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(PermissionError, "invalid_mission_transition"),
            ):
                self.transition(mission, operation)
        self.transition(mission, "cancel")
        with self.assertRaises(PermissionError):
            self.transition(mission, "start")
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM authorization_events WHERE reason='invalid_mission_transition'"
                ).fetchone()[0],
                3,
            )

    def test_only_one_active_mission_per_uav_even_with_concurrent_starts(self):
        missions = [self.create("One"), self.create("Two")]
        self.now += 1000

        def start(mission):
            try:
                MissionService(self.path, clock=lambda: self.now).transition(
                    self.token, UAV, mission["mission_id"], "start"
                )
                return "active"
            except PermissionError as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(start, missions))
        self.assertCountEqual(outcomes, ["active", "mission_already_active"])

    def test_new_telemetry_only_links_during_active_capture_window(self):
        self.guard(self.record("before"), IDENTITY)
        mission = self.create()
        self.guard(self.record("planned"), IDENTITY)
        started = self.transition(mission, "start")
        self.guard(
            self.record("late-old", captured=started["started_at_us"] - 1), IDENTITY
        )
        self.guard(self.record("future", captured=self.now + 1), IDENTITY)
        self.guard(self.record("inside"), IDENTITY)
        self.guard(self.record("inside"), IDENTITY)
        self.transition(mission, "complete")
        self.guard(self.record("after"), IDENTITY)
        self.assertEqual(
            [r["record"]["record_id"] for r in self.linked(mission)["telemetry"]],
            ["inside"],
        )
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 6
            )

    def test_completed_link_cannot_move_to_next_mission_and_retry_does_not_relink(self):
        first = self.create("First")
        self.transition(first, "start")
        old = self.record("old")
        self.guard(old, IDENTITY)
        self.transition(first, "complete")
        second = self.create("Second")
        self.transition(second, "start")
        self.guard(old, IDENTITY)
        self.assertEqual(len(self.linked(first)["telemetry"]), 1)
        self.assertEqual(self.linked(second)["telemetry"], [])
        with self.assertRaises(sqlite3.IntegrityError):
            with database_transaction(self.path) as db:
                db.execute(
                    "UPDATE mission_telemetry SET mission_id=?", (second["mission_id"],)
                )

    def test_wrong_signing_key_does_not_create_link(self):
        mission = self.create()
        self.transition(mission, "start")
        with self.assertRaises(ValueError):
            self.guard(self.record(key="b" * 64), IDENTITY)
        self.assertEqual(self.linked(mission)["telemetry"], [])

    def test_cross_uav_links_and_mission_lookup_are_rejected(self):
        mission = self.create()
        self.transition(mission, "start")
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO uavs(uav_id,name,system_id,certificate_identity,signing_key_id,status) "
                "VALUES ('other','Other',2,'urn:sentinel:uav:2','other-key','active')"
            )
            db.execute(
                "INSERT INTO uav_assignments(user_id,uav_id) VALUES ('fixture-user','other')"
            )
            db.execute(
                "INSERT INTO telemetry_records VALUES ('other-record','other',?,?, 'HEARTBEAT',2,1,"
                "'authenticated_uav_gateway','gateway_attested','{}')",
                (self.now, self.now),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            with database_transaction(self.path) as db:
                db.execute(
                    "INSERT INTO mission_telemetry VALUES (?,?,?,?)",
                    ("other-record", UAV, mission["mission_id"], self.now),
                )
        with self.assertRaisesRegex(PermissionError, "mission_not_found"):
            self.service.get(self.token, "other", mission["mission_id"])

    def test_viewer_can_read_but_cannot_mutate_and_operator_can_manage_assigned_uav(
        self,
    ):
        viewer, _ = self.user("Viewer", "B")
        operator, _ = self.user("Operator", "C")
        mission = self.create(token=operator)
        self.assertEqual(
            self.service.get(viewer, UAV, mission["mission_id"])["status"], "planned"
        )
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            self.create(token=viewer)
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            self.service.transition(viewer, UAV, mission["mission_id"], "start")

    def test_revocation_unassignment_role_change_and_inactive_uav_take_effect(self):
        operator, actor = self.user("Operator", "D")
        mission = self.create(token=operator)
        with database_transaction(self.path) as db:
            db.execute("DELETE FROM uav_assignments WHERE user_id=?", (actor,))
        with self.assertRaisesRegex(PermissionError, "uav_unassigned"):
            self.service.get(operator, UAV, mission["mission_id"])
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO uav_assignments(user_id,uav_id) VALUES (?,?)", (actor, UAV)
            )
            db.execute("UPDATE users SET role_name='Viewer' WHERE user_id=?", (actor,))
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            self.service.transition(operator, UAV, mission["mission_id"], "start")
        with database_transaction(self.path) as db:
            db.execute("UPDATE users SET status='revoked' WHERE user_id=?", (actor,))
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.service.get(operator, UAV, mission["mission_id"])
        with database_transaction(self.path) as db:
            db.execute("UPDATE uavs SET status='suspended'")
        with self.assertRaisesRegex(PermissionError, "uav_inactive"):
            self.service.get(self.token, UAV, mission["mission_id"])

    def test_unassigned_admin_and_expired_session_cannot_bypass_checks(self):
        unassigned, _ = self.user("Administrator", "E", assigned=False)
        with self.assertRaisesRegex(PermissionError, "uav_unassigned"):
            self.create(token=unassigned)
        with database_transaction(self.path) as db:
            db.execute(
                "UPDATE sessions SET expires_at_epoch=? WHERE token_hash=?",
                (self.now // 1000000, _token_hash(self.token)),
            )
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.create()

    def test_list_filters_and_equal_timestamp_pagination(self):
        missions = [self.create("Mission " + str(i)) for i in range(5)]
        self.transition(missions[0], "cancel")
        first = self.service.history(self.token, UAV, limit=2)
        second = self.service.history(
            self.token, UAV, limit=2, before=first["next_before"]
        )
        third = self.service.history(
            self.token, UAV, limit=2, before=second["next_before"]
        )
        ids = [m["mission_id"] for p in (first, second, third) for m in p["missions"]]
        self.assertEqual(len(set(ids)), 5)
        self.assertIsNone(third["next_before"])
        self.assertEqual(
            len(self.service.history(self.token, UAV, status="cancelled")["missions"]),
            1,
        )
        end = (EPOCH + timedelta(microseconds=missions[0]["created_at_us"])).isoformat()
        self.assertEqual(self.service.history(self.token, UAV, end=end)["missions"], [])

    def test_linked_telemetry_pagination_is_time_bounded(self):
        mission = self.create()
        self.transition(mission, "start")
        for record_id in ("c", "a", "b"):
            self.guard(self.record(record_id), IDENTITY)
        first = self.linked(mission, limit=2)
        second = self.linked(mission, limit=2, cursor=first["next_cursor"])
        self.assertEqual(
            [
                r["record"]["record_id"]
                for r in first["telemetry"] + second["telemetry"]
            ],
            ["a", "b", "c"],
        )
        stamp = (EPOCH + timedelta(microseconds=self.now)).isoformat()
        self.assertEqual(
            self.service.telemetry(
                self.token, UAV, mission["mission_id"], "1970-01-01T00:00:00Z", stamp
            )["telemetry"],
            [],
        )

    def test_clock_regression_cannot_reorder_lifecycle_or_end_before_linked_record(
        self,
    ):
        mission = self.create()
        self.now -= 1
        with self.assertRaisesRegex(PermissionError, "mission_clock_regressed"):
            self.service.transition(self.token, UAV, mission["mission_id"], "start")
        self.now += 2000
        self.service.transition(self.token, UAV, mission["mission_id"], "start")
        self.now += 1000
        self.guard(self.record(), IDENTITY)
        self.now -= 1
        with self.assertRaisesRegex(PermissionError, "mission_clock_regressed"):
            self.service.transition(self.token, UAV, mission["mission_id"], "complete")

    def test_mission_and_audit_failures_roll_back_creation_and_ingest(self):
        with patch(
            "database.mission_repository.append_event",
            side_effect=OSError("audit unavailable"),
        ):
            with self.assertRaises(OSError):
                self.create()
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM missions").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM mission_events").fetchone()[0], 0
            )
        mission = self.create()
        self.transition(mission, "start")
        with database_transaction(self.path) as db:
            db.execute(
                "CREATE TRIGGER injected_link_failure BEFORE INSERT ON mission_telemetry BEGIN "
                "SELECT RAISE(ABORT,'injected failure'); END"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.guard(self.record(), IDENTITY)
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM mission_telemetry").fetchone()[0], 0
            )

    def test_invalid_input_and_sql_literals_do_not_modify_schema(self):
        for name in ("", " " * 3, "x" * 129, "bad\nname"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.create(name)
        for details in (
            [],
            {"not-finite": float("nan")},
            {"secret-sized": "x" * 9000},
            {1: "key"},
        ):
            with self.subTest(details=str(details)[:40]), self.assertRaises(ValueError):
                self.service.create(self.token, UAV, "Invalid", details=details)
        name = "Patrol'); DROP TABLE missions; --"
        self.assertEqual(self.create(name)["name"], name)
        for options in (
            {"limit": True},
            {"limit": 1001},
            {"status": []},
            {"before": [1, "bad"]},
            {"start": "invalid-time"},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.service.history(self.token, UAV, **options)
