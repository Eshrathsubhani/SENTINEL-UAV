"""Verify maintenance copies, restore sessions and failure cleanup."""

from contextlib import closing, redirect_stderr
from hashlib import sha256
from io import StringIO
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from database.identity_database import initialize_database
from scripts import phase5_storage_tools as tools
from security.authentication.auth_service import AuthService


class StorageToolsTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source.sqlite3"
        self.destination = self.root / "copy.sqlite3"
        initialize_database(self.source)
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute(
                """INSERT INTO users
                   (user_id,username,password_hash,role_name)
                   VALUES ('test-user','test-user',
                           '$argon2id$fixture','Administrator')"""
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,?,10,20,NULL)",
                ("a" * 64, "test-user"),
            )

    def test_backup_is_verified_and_source_is_unchanged(self):
        before = self.source.read_bytes()
        result = tools.copy_database(self.source, self.destination)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(
            result["sha256"],
            sha256(self.destination.read_bytes()).hexdigest(),
        )
        with closing(sqlite3.connect(self.destination)) as db, db:
            tools.verify(db)
            self.assertIsNone(
                db.execute("SELECT revoked_at_epoch FROM sessions")
                .fetchone()[0]
            )

    def test_restore_revokes_sessions_only_in_destination(self):
        tools.copy_database(
            self.source, self.destination, revoke_sessions=True
        )
        with closing(sqlite3.connect(self.destination)) as db, db:
            self.assertIsNotNone(
                db.execute("SELECT revoked_at_epoch FROM sessions")
                .fetchone()[0]
            )
        with closing(sqlite3.connect(self.source)) as db, db:
            self.assertIsNone(
                db.execute("SELECT revoked_at_epoch FROM sessions")
                .fetchone()[0]
            )

    def test_existing_destination_is_never_overwritten(self):
        self.destination.write_bytes(b"preserve this file")
        with self.assertRaises(FileExistsError):
            tools.copy_database(self.source, self.destination)
        self.assertEqual(
            self.destination.read_bytes(), b"preserve this file"
        )

    def test_missing_source_creates_no_destination(self):
        with self.assertRaises(FileNotFoundError):
            tools.copy_database(
                self.root / "missing.sqlite3", self.destination
            )
        self.assertFalse(self.destination.exists())

    def test_corrupt_source_removes_partial_destination(self):
        self.source.write_bytes(b"not a SQLite database")
        with self.assertRaises(sqlite3.DatabaseError):
            tools.copy_database(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_unsupported_schema_is_rejected(self):
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("PRAGMA user_version=99")
        with self.assertRaises(ValueError):
            tools.copy_database(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_foreign_key_corruption_is_rejected(self):
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute(
                """INSERT INTO uav_assignments(user_id,uav_id)
                   VALUES ('missing-user','missing-uav')"""
            )
        with self.assertRaises(ValueError):
            tools.copy_database(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_verification_failure_removes_partial_destination(self):
        with patch.object(
            tools, "verify", side_effect=RuntimeError("test failure")
        ):
            with self.assertRaises(RuntimeError):
                tools.copy_database(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_viewer_cannot_use_maintenance_cli(self):
        authentication_db = self.root / "authentication.sqlite3"
        auth = AuthService(authentication_db)
        password = "Maintenance-test-password"
        auth.bootstrap_admin("admin", password)
        token = auth.login("admin", password)
        auth.create_user(token, "viewer", password, "Viewer")
        auth.logout(token)

        arguments = [
            "phase5_storage_tools",
            "--database", str(authentication_db),
            "--username", "viewer",
            "--destination", str(self.destination),
            "backup",
        ]
        errors = StringIO()
        with patch("sys.argv", arguments), patch.object(
            tools, "getpass", return_value=password
        ), redirect_stderr(errors):
            with self.assertRaises(SystemExit) as stopped:
                tools.main()

        self.assertEqual(stopped.exception.code, 1)
        self.assertIn("role_denied", errors.getvalue())
        self.assertNotIn(password, errors.getvalue())
        self.assertFalse(self.destination.exists())