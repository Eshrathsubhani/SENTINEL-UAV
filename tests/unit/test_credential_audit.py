"""Verify that credential changes survive restarts without exposing identifiers."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from security.credential_audit import audit_credentials


class CredentialAuditTest(unittest.TestCase):
    def test_rotation_and_retirement_without_duplicate_restart_events(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            initial = {"mavlink_signing_key": "old-key-id", "tls_certificate": "old-cert-id"}
            replacement = {"mavlink_signing_key": "new-key-id", "tls_certificate": "new-cert-id"}
            with self.assertLogs("security.credential_audit") as audit:
                audit_credentials(path, "uav", initial)
                audit_credentials(path, "uav", initial)
                audit_credentials(path, "gcs", {"tls_certificate": "gcs-id"})
                audit_credentials(path, "uav", replacement)
                audit_credentials(path, "uav", {"tls_certificate": "new-cert-id"})

            self.assertEqual(len(audit.output), 8)
            self.assertIn("credential_rotated role=uav kind=mavlink_signing_key", audit.output[4])
            self.assertIn("credential_rotated role=uav kind=tls_certificate", audit.output[6])
            self.assertNotIn("-id", "\n".join(audit.output))
            with closing(sqlite3.connect(path)) as database:
                self.assertEqual(database.execute(
                    "SELECT COUNT(*) FROM credential_events WHERE role = 'uav' AND event = 'retired'"
                ).fetchone(), (3,))
