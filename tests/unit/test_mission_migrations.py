"""Schema-8 preservation, rollback and idempotent mission-schema setup."""

from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from database import migrations
from database.connection import database_transaction
from database.identity_database import initialize_database

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"


class MissionMigrationTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text(encoding="utf-8"))
        with database_transaction(self.path) as db:
            for migration in migrations.MIGRATIONS[4:8]:
                migration(db)
            db.execute("PRAGMA user_version=8")
            db.execute(
                "INSERT INTO telemetry_records VALUES ('historic','fixture-uav',1,2,'HEARTBEAT',1,1,"
                "'authenticated_uav_gateway','gateway_attested','{}')"
            )

    def test_schema8_data_survives_without_invented_historical_missions(self):
        with database_transaction(self.path, write=False) as db:
            tables = [
                r[0]
                for r in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            before = {
                t: [tuple(r) for r in db.execute("SELECT * FROM " + t)] for t in tables
            }
        initialize_database(self.path)
        initialize_database(self.path)
        with database_transaction(self.path, write=False) as db:
            self.assertTrue(
                all(
                    [tuple(r) for r in db.execute("SELECT * FROM " + t)] == rows
                    for t, rows in before.items()
                )
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM missions").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM mission_telemetry").fetchone()[0], 0
            )
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 10)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_failed_schema9_migration_rolls_back_tables_indexes_and_version(self):
        original = migrations.version_9

        def broken(db):
            original(db)
            raise RuntimeError("injected migration failure")

        with patch.object(
            migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:8], broken)
        ):
            with self.assertRaises(RuntimeError):
                initialize_database(self.path)
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 8)
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'mission%'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name='telemetry_record_uav'"
                ).fetchone()[0],
                0,
            )
        initialize_database(self.path)
