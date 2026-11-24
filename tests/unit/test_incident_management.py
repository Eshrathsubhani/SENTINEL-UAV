"""Incident evidence boundaries, lifecycle durability and current authorization."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.incidents.incident_service import IncidentService
from database import migrations
from database.connection import database_transaction
from database.identity_database import initialize_database
from database.security_event_repository import append_event
from security.authentication.auth_service import _token_hash

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"


class IncidentManagementTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text())
        initialize_database(self.path)
        self.now = 1790000000000000
        self.token = "A" * 43
        self.service = IncidentService(self.path, clock=lambda: self.now)
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO sessions VALUES (?,'fixture-user',0,2000000000,NULL)",
                (_token_hash(self.token),),
            )
            self.event = append_event(
                db,
                "test_gateway",
                "replay",
                "mavlink_rejected",
                severity="medium",
                outcome="deny",
                uav_id="fixture-uav",
                details={"reason": "replay_or_out_of_order"},
            )

    def create(self, **kwargs):
        return self.service.create(
            self.token,
            "Replay investigation",
            attack_type="replay",
            severity="high",
            **kwargs,
        )

    def user(self, role, letter):
        token = letter * 43
        actor = "user-" + letter
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO users(user_id,username,password_hash,role_name) VALUES (?,?,?,?)",
                (actor, actor, "$argon2id$fixture", role),
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,?,0,2000000000,NULL)",
                (_token_hash(token), actor),
            )
        return token, actor

    def test_full_investigation_link_note_resolution_and_restart(self):
        case = self.create(uav_id="fixture-uav", security_event_ids=[self.event])
        identity = case["incident_id"]
        self.assertEqual(case["status"], "open")
        self.now += 1
        self.assertEqual(
            self.service.investigate(self.token, identity)["status"], "investigating"
        )
        self.service.add_note(
            self.token, identity, "Compared signing timestamps with source logs."
        )
        self.service.classify(self.token, identity, "replay", "critical")
        self.now += 1
        resolved = self.service.resolve(
            self.token, identity, "Confirmed local replay fixture; test completed."
        )
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["resolved_at_us"], self.now)
        self.assertEqual(resolved["severity"], "critical")
        restarted = IncidentService(self.path, clock=lambda: self.now)
        self.assertEqual(restarted.get(self.token, identity)["linked_event_count"], 1)
        self.assertEqual(
            restarted.page(self.token, identity, "notes")["notes"][0]["body"],
            "Compared signing timestamps with source logs.",
        )
        history = restarted.page(self.token, identity, "history")["history"]
        self.assertTrue(all(r["actor_id"] == "fixture-user" for r in history))
        self.assertEqual(len(history), 6)
        with database_transaction(self.path, write=False) as db:
            rows = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM security_events WHERE category='incident'"
                )
            ]
        self.assertEqual(len(rows), 6)
        self.assertNotIn("Compared signing", json.dumps(rows))
        self.assertNotIn(resolved["resolution"], json.dumps(rows))

    def test_duplicate_links_are_idempotent_and_evidence_cannot_be_deleted(self):
        case = self.create(security_event_ids=[self.event, self.event])
        self.service.link_events(self.token, case["incident_id"], [self.event])
        self.assertEqual(
            self.service.get(self.token, case["incident_id"])["linked_event_count"], 1
        )
        links = self.service.page(self.token, case["incident_id"], "events")["events"]
        self.assertEqual(links[0]["event_id"], self.event)
        self.assertEqual(links[0]["details"]["reason"], "replay_or_out_of_order")
        with self.assertRaises(sqlite3.IntegrityError):
            with database_transaction(self.path) as db:
                db.execute(
                    "DELETE FROM security_events WHERE event_id=?", (self.event,)
                )

    def test_unknown_event_batch_and_scope_mismatch_cannot_partially_mutate(self):
        with self.assertRaisesRegex(PermissionError, "security_event_not_found"):
            self.create(security_event_ids=[self.event, 9223372036854775806])
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0
            )
        case = self.create(uav_id="fixture-uav")
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO uavs(uav_id,name,system_id,certificate_identity,signing_key_id,status) "
                "VALUES ('other','Other',2,'urn:other','key','active')"
            )
            other = append_event(db, "test", "tls", "rejected", uav_id="other")
        with self.assertRaisesRegex(PermissionError, "incident_event_uav_mismatch"):
            self.service.link_events(
                self.token, case["incident_id"], [self.event, other]
            )
        self.assertEqual(
            self.service.get(self.token, case["incident_id"])["linked_event_count"], 0
        )
        with self.assertRaises(sqlite3.IntegrityError):
            with database_transaction(self.path) as db:
                db.execute(
                    "INSERT INTO incident_event_links(incident_id,security_event_id,actor_id,linked_at_us) VALUES (?,?,?,?)",
                    (case["incident_id"], other, "fixture-user", self.now),
                )

    def test_systemwide_case_can_link_uav_and_global_events(self):
        with database_transaction(self.path) as db:
            global_event = append_event(db, "test", "tls", "handshake_failed")
        case = self.create(security_event_ids=[self.event, global_event])
        self.assertIsNone(case["uav_id"])
        self.assertEqual(case["linked_event_count"], 2)

    def test_operator_viewer_invalid_sessions_and_permission_removal_are_denied(self):
        case = self.create()
        for role, letter in (("Operator", "B"), ("Viewer", "C")):
            token, _ = self.user(role, letter)
            for operation in (
                lambda: self.service.get(token, case["incident_id"]),
                lambda: self.service.create(token, "Blocked"),
                lambda: self.service.add_note(token, case["incident_id"], "Blocked"),
                lambda: self.service.list(token),
            ):
                with (
                    self.subTest(role=role),
                    self.assertRaisesRegex(PermissionError, "role_denied"),
                ):
                    operation()
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.service.list("invalid-token")
        with database_transaction(self.path) as db:
            db.execute(
                "DELETE FROM role_permissions WHERE role_name='Administrator' AND permission_name='audit.read'"
            )
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            self.service.get(self.token, case["incident_id"])

    def test_current_role_revocation_session_expiry_and_logout_apply_immediately(self):
        token, actor = self.user("Administrator", "D")
        self.service.list(token)
        with database_transaction(self.path) as db:
            db.execute(
                "UPDATE users SET role_name='Operator' WHERE user_id=?", (actor,)
            )
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            self.service.list(token)
        with database_transaction(self.path) as db:
            db.execute(
                "UPDATE users SET role_name='Administrator',status='revoked' WHERE user_id=?",
                (actor,),
            )
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.service.list(token)
        with database_transaction(self.path) as db:
            db.execute(
                "UPDATE sessions SET expires_at_epoch=? WHERE token_hash=?",
                (self.now // 1000000, _token_hash(self.token)),
            )
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.service.list(self.token)
        token, _ = self.user("Administrator", "E")
        self.service.auth.logout(token)
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            self.service.list(token)

    def test_security_review_retains_access_to_revoked_uav_evidence(self):
        with database_transaction(self.path) as db:
            db.execute("UPDATE uavs SET status='revoked'")
        case = self.create(uav_id="fixture-uav", security_event_ids=[self.event])
        self.assertEqual(
            self.service.get(self.token, case["incident_id"])["linked_event_count"], 1
        )
        with self.assertRaisesRegex(PermissionError, "unknown_uav"):
            self.create(uav_id="missing")

    def test_terminal_case_rejects_further_mutations_and_requires_resolution(self):
        case = self.create()
        identity = case["incident_id"]
        with self.assertRaises(ValueError):
            self.service.resolve(self.token, identity, " ")
        self.service.resolve(
            self.token, identity, "Functional test closed without a real attack."
        )
        for operation in (
            lambda: self.service.investigate(self.token, identity),
            lambda: self.service.add_note(self.token, identity, "late note"),
            lambda: self.service.link_events(self.token, identity, [self.event]),
            lambda: self.service.classify(self.token, identity, "other", "low"),
            lambda: self.service.resolve(self.token, identity, "Again"),
        ):
            with (
                self.subTest(operation=str(operation)),
                self.assertRaisesRegex(PermissionError, "incident_resolved"),
            ):
                operation()

    def test_repeated_investigation_is_denied_and_noop_classification_creates_no_history(
        self,
    ):
        case = self.create()
        identity = case["incident_id"]
        self.service.investigate(self.token, identity)
        with self.assertRaisesRegex(PermissionError, "invalid_incident_transition"):
            self.service.investigate(self.token, identity)
        before = self.service.page(self.token, identity, "history")
        self.service.classify(self.token, identity, "replay", "high")
        self.assertEqual(self.service.page(self.token, identity, "history"), before)

    def test_list_filters_time_ranges_and_pagination_at_equal_timestamps(self):
        cases = [self.create(uav_id="fixture-uav") for _ in range(5)]
        self.service.resolve(self.token, cases[0]["incident_id"], "Closed test.")
        page = self.service.list(self.token, limit=2)
        identities = []
        while True:
            identities.extend(r["incident_id"] for r in page["incidents"])
            if page["next_before"] is None:
                break
            page = self.service.list(self.token, limit=2, before=page["next_before"])
        self.assertEqual(len(set(identities)), 5)
        self.assertEqual(
            len(
                self.service.list(
                    self.token,
                    status="resolved",
                    severity="high",
                    attack_type="replay",
                    uav_id="fixture-uav",
                )["incidents"]
            ),
            1,
        )
        self.assertEqual(
            self.service.list(self.token, end="1970-01-02T00:00:00Z")["incidents"], []
        )
        self.assertEqual(
            self.service.list(self.token, uav_id="' OR 1=1 --")["incidents"], []
        )

    def test_notes_events_and_history_are_bounded_and_paginated(self):
        case = self.create()
        identity = case["incident_id"]
        for i in range(5):
            self.service.add_note(self.token, identity, "Note " + str(i))
        page = self.service.page(self.token, identity, "notes", limit=2)
        ids = []
        while True:
            ids.extend(r["note_id"] for r in page["notes"])
            if page["next_before"] is None:
                break
            page = self.service.page(
                self.token, identity, "notes", limit=2, before=page["next_before"]
            )
        self.assertEqual(len(set(ids)), 5)
        self.assertEqual(
            len(self.service.page(self.token, identity, "history", limit=2)["history"]),
            2,
        )

    def test_clock_regression_is_denied_without_changing_history(self):
        case = self.create()
        identity = case["incident_id"]
        self.now -= 1
        with self.assertRaisesRegex(PermissionError, "incident_clock_regressed"):
            self.service.add_note(self.token, identity, "Late")
        self.assertEqual(self.service.get(self.token, identity)["note_count"], 0)

    def test_storage_failure_rolls_back_incident_note_and_central_audit(self):
        with patch(
            "database.incident_repository.append_event",
            side_effect=sqlite3.OperationalError("storage failed"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.create()
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0
            )
        case = self.create()
        with patch(
            "database.incident_repository.append_event",
            side_effect=sqlite3.OperationalError("storage failed"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.service.add_note(self.token, case["incident_id"], "Must roll back")
        self.assertEqual(
            self.service.get(self.token, case["incident_id"])["note_count"], 0
        )

    def test_concurrent_notes_and_duplicate_links_do_not_lose_data(self):
        case = self.create()
        identity = case["incident_id"]

        def write(index):
            service = IncidentService(self.path, clock=lambda: self.now)
            service.add_note(self.token, identity, "Concurrent note " + str(index))
            service.link_events(self.token, identity, [self.event])

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(write, range(5)))
        current = self.service.get(self.token, identity)
        self.assertEqual(current["note_count"], 5)
        self.assertEqual(current["linked_event_count"], 1)

    def test_invalid_input_and_sql_literals_are_safe(self):
        for kwargs in (
            {"attack_type": "unknown"},
            {"severity": []},
            {"security_event_ids": [True]},
            {"security_event_ids": [2**100]},
            {"description": "x" * 4097},
        ):
            with self.subTest(kwargs=str(kwargs)[:50]), self.assertRaises(ValueError):
                self.service.create(self.token, "Invalid", **kwargs)
        for filters in (
            {"limit": True},
            {"limit": 1001},
            {"before": [1, "bad"]},
            {"status": []},
            {"start": "invalid"},
            {"start": "2026-01-02T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
        ):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                self.service.list(self.token, **filters)
        title = "Test'); DROP TABLE incidents; --"
        case = self.service.create(self.token, title)
        self.assertEqual(case["title"], title)
        for component, before in (
            ("invalid", None),
            ("notes", True),
            ("history", 2**100),
        ):
            with self.subTest(component=component), self.assertRaises(ValueError):
                self.service.page(
                    self.token, case["incident_id"], component, before=before
                )

    def test_migration9_preserves_existing_records_and_creates_no_invented_incidents(
        self,
    ):
        old = self.path.with_name("old.sqlite3")
        with closing(sqlite3.connect(old)) as db:
            db.executescript(FIXTURE.read_text())
        with database_transaction(old) as db:
            for migration in migrations.MIGRATIONS[4:9]:
                migration(db)
            db.execute("PRAGMA user_version=9")
            before = [tuple(r) for r in db.execute("SELECT * FROM security_events")]
        initialize_database(old)
        initialize_database(old)
        with database_transaction(old, write=False) as db:
            self.assertEqual(
                [tuple(r) for r in db.execute("SELECT * FROM security_events")], before
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0
            )
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 10)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_failed_schema10_upgrade_rolls_back_all_new_tables_and_version(self):
        old = self.path.with_name("failed.sqlite3")
        with database_transaction(old) as db:
            for i, migration in enumerate(migrations.MIGRATIONS[:9], 1):
                migration(db)
                db.execute("PRAGMA user_version=" + str(i))
        original = migrations.version_10

        def broken(db):
            original(db)
            raise RuntimeError("injected upgrade failure")

        with patch.object(
            migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:9], broken)
        ):
            with self.assertRaises(RuntimeError):
                initialize_database(old)
        with database_transaction(old, write=False) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 9)
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'incident%'"
                ).fetchone()[0],
                0,
            )
        initialize_database(old)
