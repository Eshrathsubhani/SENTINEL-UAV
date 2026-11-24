"""Security projections, access boundaries and durable producer retries."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock, patch

from backend.security.event_service import SecurityEventService
from database import migrations
from database.connection import connect_database, database_transaction
from database.identity_database import initialize_database
from database.security_event_repository import append_event
from security.authentication.auth_service import (
    AuthenticationError,
    AuthService,
    _token_hash,
)
from security.credential_audit import audit_credentials
from security.event_sink import SecurityEventSink
from security.mavlink_signing import SignedTelemetryReceiver

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"


class SecurityEventTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text(encoding="utf-8"))
        with database_transaction(self.path) as db:
            for migration in migrations.MIGRATIONS[4:7]:
                migration(db)
            db.execute("PRAGMA user_version=7")
        initialize_database(self.path)
        self.sink = SecurityEventSink(self.path, "test_gateway")

    def rows(self, category=None):
        with database_transaction(self.path, write=False) as db:
            if category:
                return [
                    dict(r)
                    for r in db.execute(
                        "SELECT * FROM security_events WHERE category=?", (category,)
                    )
                ]
            return [dict(r) for r in db.execute("SELECT * FROM security_events")]

    def session(self, role, letter):
        token = letter * 43
        user_id = "user-" + role
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO users (user_id,username,password_hash,role_name) VALUES (?,?,?,?)",
                (user_id, user_id, "$argon2id$fixture-only", role),
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,NULL)",
                (_token_hash(token), user_id, 0, int(time.time()) + 10000),
            )
        return token, user_id

    def test_backfill_preserves_old_data_and_does_not_repeat_on_restart(self):
        rows = self.rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            {r["producer"] for r in rows},
            {"identity_events", "authorization_events", "command_requests"},
        )
        self.assertEqual(
            next(r for r in rows if r["producer"] == "identity_events")["uav_id"],
            "fixture-uav",
        )
        initialize_database(self.path)
        self.assertEqual(self.rows(), rows)
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM command_requests").fetchone()[0], 1
            )
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_source_and_projection_rollback_together(self):
        count = len(self.rows())
        with self.assertRaises(RuntimeError):
            with database_transaction(self.path) as db:
                db.execute(
                    "INSERT INTO identity_events(event,reason) VALUES ('login_failed','invalid_password')"
                )
                raise RuntimeError("rollback")
        self.assertEqual(len(self.rows()), count)
        with database_transaction(self.path) as db:
            db.execute(
                "INSERT INTO identity_events(event,reason) VALUES ('login_failed','invalid_password')"
            )
        self.assertEqual(self.rows("authentication")[0]["severity"], "medium")

    def test_failed_schema8_upgrade_leaves_schema7_intact(self):
        other = self.path.with_name("old.sqlite3")
        with closing(sqlite3.connect(other)) as db:
            db.executescript(FIXTURE.read_text())
        with database_transaction(other) as db:
            for migration in migrations.MIGRATIONS[4:7]:
                migration(db)
            db.execute("PRAGMA user_version=7")
        real = migrations.MIGRATIONS[7]

        def broken(db):
            real(db)
            raise RuntimeError("after installation")

        with patch.object(
            migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:7], broken)
        ):
            with self.assertRaises(RuntimeError):
                initialize_database(other)
        with database_transaction(other, write=False) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 7)
            self.assertIsNone(
                db.execute(
                    "SELECT name FROM sqlite_master WHERE name='security_events'"
                ).fetchone()
            )
        initialize_database(other)

    def test_producer_retries_are_idempotent_and_conflicts_are_rejected(self):
        kwargs = dict(
            producer_event_id="stable-id",
            occurred_at_us=100,
            details={"reason": "unsigned"},
        )
        first = self.sink("mavlink_signing", "mavlink_rejected", **kwargs)
        self.assertEqual(
            self.sink("mavlink_signing", "mavlink_rejected", **kwargs), first
        )
        with self.assertRaises(ValueError):
            self.sink("mavlink_signing", "different_event", **kwargs)
        self.assertEqual(len(self.rows("mavlink_signing")), 1)

    def test_payloads_secrets_invalid_metadata_and_unknown_uavs_rejected(self):
        for details in (
            {"password": "secret"},
            {"reason": "a secret value"},
            {"reason": {"raw": "frame"}},
        ):
            with self.subTest(details=details), self.assertRaises(ValueError):
                self.sink("tls", "rejected", details=details)
        with self.assertRaises(sqlite3.IntegrityError):
            self.sink("tls", "rejected", uav_id="missing-uav")
        self.assertEqual(self.rows("tls"), [])

    def test_admin_can_filter_time_severity_uav_and_paginate_without_duplicates(self):
        token, _ = self.session("Administrator", "A")
        for number in range(5):
            self.sink(
                "tls",
                "handshake_failed",
                severity="high",
                outcome="deny",
                uav_id="fixture-uav",
                occurred_at_us=1_000_000 + number,
            )
        service = SecurityEventService(self.path)
        filters = dict(
            category="tls",
            severity="high",
            uav_id="fixture-uav",
            start="1970-01-01T00:00:01+00:00",
            end="1970-01-01T00:00:02+00:00",
            limit=2,
        )
        page = service.query(token, **filters)
        ids = [r["event_id"] for r in page["events"]]
        while page["next_before"]:
            page = service.query(token, before=page["next_before"], **filters)
            ids.extend(r["event_id"] for r in page["events"])
        self.assertEqual(len(ids), 5)
        self.assertEqual(len(set(ids)), 5)
        self.assertEqual(
            service.query(token, category="tls", uav_id="' OR 1=1 --")["events"], []
        )

    def test_operator_sees_only_own_events_and_viewer_cannot_read_audit(self):
        operator, actor = self.session("Operator", "B")
        viewer, _ = self.session("Viewer", "C")
        self.sink("identity", "own_event", actor_id=actor)
        self.sink("identity", "other_event", actor_id="fixture-user")
        service = SecurityEventService(self.path)
        rows = service.query(operator, category="identity")["events"]
        self.assertEqual([r["event"] for r in rows], ["own_event"])
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            service.query(viewer)
        self.assertEqual(self.rows("authorization")[-1]["outcome"], "deny")

    def test_existing_session_is_denied_after_role_or_account_revocation(self):
        token, actor = self.session("Operator", "D")
        service = SecurityEventService(self.path)
        service.query(token)
        with database_transaction(self.path) as db:
            db.execute("UPDATE users SET status='revoked' WHERE user_id=?", (actor,))
        with self.assertRaisesRegex(PermissionError, "invalid_session"):
            service.query(token)

    def test_invalid_filters_fail_cleanly(self):
        service = SecurityEventService(self.path)
        for filters in (
            {"category": "invalid"},
            {"severity": "invalid"},
            {"limit": 0},
            {"limit": True},
            {"before": [1]},
            {"before": [1, 2**100]},
            {"category": []},
            {"start": "not-a-time"},
            {"start": "2026-01-02T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
        ):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                service.query("invalid", **filters)

    def test_administrative_failure_rolls_back_mutation_but_preserves_safe_failure_event(
        self,
    ):
        token, actor = self.session("Administrator", "E")
        auth = AuthService(self.path)
        with self.assertRaisesRegex(RuntimeError, "private input"):
            with auth.administrator_transaction(
                token, "users.manage", "fixture-user"
            ) as (db, _):
                db.execute(
                    "UPDATE users SET username='changed' WHERE user_id='fixture-user'"
                )
                raise RuntimeError("private input")
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(
                db.execute(
                    "SELECT username FROM users WHERE user_id='fixture-user'"
                ).fetchone()[0],
                "fixture-admin",
            )
        event = next(
            r for r in self.rows() if r["event"] == "administrative_action_failed"
        )
        self.assertEqual(event["actor_id"], actor)
        self.assertEqual(event["outcome"], "failure")
        self.assertNotIn("private input", json.dumps(event))

    def test_command_policy_and_communication_changes_are_projected(self):
        with database_transaction(self.path) as db:
            db.execute(
                "UPDATE command_requests SET status='failed',reason='connection_failed'"
            )
            db.execute("UPDATE policies SET version=version+1")
            db.execute(
                "INSERT INTO communication_events(uav_id,occurred_at_us,event,source,reason) "
                "VALUES ('fixture-uav',123,'heartbeat_lost','gcs_accepted_heartbeat','accepted_heartbeat_timeout')"
            )
        events = {r["event"]: r for r in self.rows()}
        self.assertEqual(events["command.failed"]["actor_id"], "fixture-user")
        self.assertNotIn("token_hash", json.dumps(events["command.failed"]))
        self.assertEqual(events["policy.updated"]["actor_id"], None)
        self.assertEqual(events["heartbeat_lost"]["severity"], "medium")

    def test_credential_source_replays_after_failure_without_duplicates_or_fingerprints(
        self,
    ):
        source = self.path.with_name("credentials.sqlite3")
        with self.assertRaises(OSError):
            audit_credentials(
                source,
                "uav",
                {"tls_certificate": "private-fingerprint"},
                on_event=Mock(side_effect=OSError("unavailable")),
            )
        audit_credentials(
            source,
            "uav",
            {"tls_certificate": "private-fingerprint"},
            on_event=self.sink,
        )
        audit_credentials(
            source,
            "uav",
            {"tls_certificate": "private-fingerprint"},
            on_event=self.sink,
        )
        self.assertEqual(len(self.rows("credential")), 1)
        audit_credentials(
            source, "uav", {"tls_certificate": "replacement"}, on_event=self.sink
        )
        self.assertEqual(
            {r["event"] for r in self.rows("credential")},
            {"credential_activated", "credential_retired", "credential_rotated"},
        )
        self.assertNotIn("private-fingerprint", json.dumps(self.rows("credential")))

    def test_signing_rejections_and_summary_are_persisted_without_frames(self):
        raw = Mock()
        verifier = Mock()
        receiver = SignedTelemetryReceiver(raw, verifier, 1, on_event=self.sink)
        message = Mock()
        message.get_type.return_value = "HEARTBEAT"
        message.get_srcSystem.return_value = 1
        message.get_srcComponent.return_value = 1
        message.get_msgbuf.return_value = b"private-frame"
        raw.recv_match.return_value = message
        for reason in (
            "unsigned",
            "invalid_signature",
            "replay_or_out_of_order",
            "timestamp_outside_window",
        ):
            verifier.verify.return_value = reason
            self.assertIsNone(receiver.recv_match())
        verifier.verify.return_value = None
        self.assertIs(receiver.recv_match(), message)
        message.get_type.return_value = "BAD_DATA"
        self.assertIsNone(receiver.recv_match())
        receiver.close()
        self.assertEqual(len(self.rows("replay")), 1)
        self.assertEqual(len(self.rows("freshness")), 1)
        summary = next(r for r in self.rows() if r["event"] == "signing_summary")
        self.assertEqual(
            json.loads(summary["details_json"]), {"accepted": 1, "rejected_total": 4}
        )
        self.assertNotIn("private-frame", json.dumps(self.rows()))

    def test_missing_event_database_is_not_silently_created(self):
        with self.assertRaises(ValueError):
            SecurityEventSink(self.path.with_name("missing.sqlite3"), "gateway")

    def test_authentication_failure_success_logout_project_without_passwords(self):
        fresh = self.path.with_name("authentication.sqlite3")
        auth = AuthService(fresh)
        auth.bootstrap_admin("audit-admin", "Test-only password 123")
        with self.assertRaises(AuthenticationError):
            auth.login("audit-admin", "Wrong password 456")
        token = auth.login("audit-admin", "Test-only password 123")
        auth.logout(token)
        with database_transaction(fresh, write=False) as db:
            events = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM security_events WHERE category='authentication'"
                )
            ]
        self.assertEqual(
            [r["event"] for r in events], ["login_failed", "login_succeeded", "logout"]
        )
        self.assertNotIn("password 123", json.dumps(events))
        self.assertNotIn(token, json.dumps(events))
