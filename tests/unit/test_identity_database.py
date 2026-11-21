"""Check persistence, constraints, permissions, and version safeguards."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from database.identity_database import connect_database, initialize_database


class IdentityDatabaseTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        initialize_database(self.path)

    def test_reinitialization_and_restart_preserve_records(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute(
                "INSERT INTO users (user_id, username, password_hash, role_name) VALUES (?, ?, ?, ?)",
                ("u1", "operator", "$argon2id$test-fixture", "Operator"),
            )
        initialize_database(self.path)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT username FROM users").fetchone()[0], "operator")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM roles").fetchone()[0], 3)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 7)

    def test_constraints_reject_duplicates_invalid_references_and_values(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("INSERT INTO users VALUES ('u1','operator','$argon2id$fixture','Operator','active',CURRENT_TIMESTAMP)")
            db.execute("INSERT INTO uavs (uav_id,name,system_id,certificate_identity,signing_key_id) VALUES ('v1','SITL',1,'urn:sentinel:uav:1','key-v1')")
            invalid = (
                ("INSERT INTO users VALUES ('u2','OPERATOR','$argon2id$x','Viewer','active',CURRENT_TIMESTAMP)", ()),
                ("INSERT INTO users VALUES ('u2','other','plaintext','Viewer','active',CURRENT_TIMESTAMP)", ()),
                ("INSERT INTO users VALUES ('u2','other','$argon2id$x','Root','active',CURRENT_TIMESTAMP)", ()),
                ("INSERT INTO uav_assignments VALUES ('missing','v1',CURRENT_TIMESTAMP)", ()),
                ("INSERT INTO uavs (uav_id,name,system_id,certificate_identity,signing_key_id) VALUES ('v2','Other',1,'urn:other','k')", ()),
                ("INSERT INTO uavs (uav_id,name,system_id,certificate_identity,signing_key_id) VALUES ('v2','Other',2,'urn:sentinel:uav:1','k')", ()),
                ("INSERT INTO sessions VALUES (?, 'u1', 10, 5, NULL)", ("a" * 64,)),
            )
            for sql, parameters in invalid:
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    db.execute(sql, parameters)
            db.execute("INSERT INTO uav_assignments (user_id,uav_id) VALUES ('u1','v1')")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO uav_assignments (user_id,uav_id) VALUES ('u1','v1')")

    def test_viewer_permissions_exclude_commands_and_administration(self):
        with closing(connect_database(self.path)) as db:
            permissions = {row[0] for row in db.execute(
                "SELECT permission_name FROM role_permissions WHERE role_name = ?", ("Viewer",)
            )}
            self.assertEqual(permissions, {"telemetry.read", "status.read"})

    def test_concurrent_initialization(self):
        fresh = self.path.with_name("concurrent.sqlite3")
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(initialize_database, [fresh, fresh]))
        with closing(connect_database(fresh)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM roles").fetchone()[0], 3)

    def test_future_schema_and_unrelated_database_are_preserved(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("PRAGMA user_version = 99")
        with self.assertRaises(ValueError):
            initialize_database(self.path)
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 99)
        other = self.path.with_name("other.sqlite3")
        with closing(sqlite3.connect(other)) as db, db:
            db.execute("CREATE TABLE unrelated (value TEXT)")
        with self.assertRaises(ValueError):
            initialize_database(other)
