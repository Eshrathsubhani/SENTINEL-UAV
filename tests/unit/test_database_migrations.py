"""Exercise real legacy layout preservation, migration rollback and lock failures."""

from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from database.connection import connect_database, database_transaction
from database.identity_database import initialize_database
from database import migrations

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "phase4_identity_v4.sql"


def contents(db):
    tables = [row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    return {name: sorted(tuple(row) for row in db.execute(f'SELECT * FROM "{name}"'))
            for name in tables}


class DatabaseMigrationTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(FIXTURE.read_text(encoding="utf-8"))

    def test_populated_original_version4_is_unchanged_on_repeated_initialization(self):
        with closing(connect_database(self.path)) as db:
            before = contents(db)
            schema = db.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
        initialize_database(self.path)
        initialize_database(self.path)
        with closing(connect_database(self.path)) as db:
            self.assertTrue(all(contents(db)[table] == rows for table, rows in before.items()))
            self.assertTrue(set(tuple(r) for r in schema).issubset(
                set(tuple(r) for r in db.execute("SELECT name, sql FROM sqlite_master ORDER BY name"))))
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 10)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def legacy_version(self, version):
        with closing(connect_database(self.path)) as db, db:
            db.execute("DROP TABLE command_requests")
            if version < 3:
                db.execute("DROP TABLE telemetry_snapshots")
            if version < 2:
                db.execute("DROP TABLE login_attempts")
            db.execute(f"PRAGMA user_version = {version}")

    def test_versions_one_two_three_upgrade_without_losing_existing_rows(self):
        original = self.path.read_bytes()
        for version in (1, 2, 3):
            with self.subTest(version=version):
                self.path.write_bytes(original)
                self.legacy_version(version)
                with closing(connect_database(self.path)) as db:
                    before = contents(db)
                initialize_database(self.path)
                with closing(connect_database(self.path)) as db:
                    after = contents(db)
                    self.assertTrue(all(after[table] == rows for table, rows in before.items()))
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 10)
                    self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                    self.assertIn("command_requests", after)
                    self.assertIn("telemetry_snapshots", after)
                    self.assertIn("login_attempts", after)

    def test_failed_migration_rolls_back_ddl_data_and_version(self):
        self.legacy_version(3)
        with closing(connect_database(self.path)) as db:
            before = contents(db)

        def failure(db):
            db.execute("CREATE TABLE partial_migration (value TEXT)")
            db.execute("UPDATE users SET username='changed'")
            raise RuntimeError("Injected migration failure")

        with patch.object(migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:3], failure, migrations.MIGRATIONS[4])):
            with self.assertRaisesRegex(RuntimeError, "Injected migration"):
                initialize_database(self.path)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(contents(db), before)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 3)
        initialize_database(self.path)

    def test_failure_after_multiple_steps_rolls_back_the_entire_upgrade(self):
        fresh = self.path.with_name("fresh.sqlite3")

        def failure(db):
            raise RuntimeError("Injected third-step failure")

        with patch.object(migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:2], failure,
                                                     migrations.MIGRATIONS[3], migrations.MIGRATIONS[4])):
            with self.assertRaises(RuntimeError):
                initialize_database(fresh)
        with closing(connect_database(fresh)) as db:
            self.assertEqual(contents(db), {})
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 0)

    def test_transaction_rolls_back_on_foreign_key_error_and_releases_connection(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with database_transaction(self.path) as db:
                db.execute("UPDATE users SET username='changed'")
                db.execute("INSERT INTO uav_assignments (user_id,uav_id) VALUES ('missing','fixture-uav')")
        with database_transaction(self.path, timeout=0) as db:
            self.assertEqual(db.execute("SELECT username FROM users").fetchone()[0], "fixture-admin")
            db.execute("UPDATE users SET username='committed'")
        with database_transaction(self.path, write=False) as db:
            self.assertEqual(db.execute("SELECT username FROM users").fetchone()[0], "committed")

    def test_busy_writer_failure_does_not_apply_changes(self):
        with database_transaction(self.path):
            with self.assertRaises(sqlite3.OperationalError):
                with database_transaction(self.path, timeout=0) as db:
                    db.execute("UPDATE users SET username='changed'")
        with database_transaction(self.path, timeout=0) as db:
            self.assertEqual(db.execute("SELECT username FROM users").fetchone()[0], "fixture-admin")

    def test_runner_requires_transaction(self):
        with closing(connect_database(self.path)) as db:
            with self.assertRaisesRegex(RuntimeError, "explicit transaction"):
                migrations.apply_migrations(db)

    def test_connections_close_after_commit_and_rollback(self):
        with database_transaction(self.path) as committed:
            pass
        with self.assertRaises(sqlite3.ProgrammingError):
            committed.execute("SELECT 1")
        with self.assertRaises(RuntimeError):
            with database_transaction(self.path) as failed:
                raise RuntimeError("failure")
        with self.assertRaises(sqlite3.ProgrammingError):
            failed.execute("SELECT 1")
