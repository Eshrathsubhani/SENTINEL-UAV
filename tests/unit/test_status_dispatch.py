"""Prove policy denials block the actual dispatcher sender boundary."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock

from backend.commands.status_request import CommandService, MAVLinkStatusSender, StatusDispatcher
from database.identity_database import connect_database, initialize_database
from security.identity.uav_registry import UAVRegistry


class StatusDispatchTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "identity.sqlite3"
        self.registry = UAVRegistry(self.path)
        self.auth = self.registry.auth
        self.user = self.auth.bootstrap_admin("admin", "admin-test-password")
        self.token = self.auth.login("admin", "admin-test-password")
        self.uav = self.registry.register(self.token, "SITL", 1, "urn:sentinel:uav:1", "a" * 64)
        self.registry.set_status(self.token, self.uav, "active")
        self.registry.assign(self.token, self.user, self.uav)
        self.service = CommandService(self.path)
        self.sender = Mock()
        self.dispatcher = StatusDispatcher(
            self.path, system_id=1, identity="urn:sentinel:uav:1",
            signing_key_id="a" * 64, sender=self.sender,
        )

    def test_allowed_status_is_sent_once_and_audited(self):
        request = self.service.request_status(self.token, self.uav)
        self.assertEqual(self.dispatcher.dispatch_one(), "sent")
        self.assertIsNone(self.dispatcher.dispatch_one())
        self.sender.assert_called_once_with(1)
        self.assertEqual(self.service.result(self.token, request)["status"], "sent")
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT decision FROM authorization_events WHERE action='command.status.dispatch'"
            ).fetchone()[0], "allow")

    def test_viewer_and_unassigned_administrator_cannot_enqueue(self):
        viewer_id = self.auth.create_user(self.token, "viewer", "viewer-test-password", "Viewer")
        viewer = self.auth.login("viewer", "viewer-test-password")
        self.registry.assign(self.token, viewer_id, self.uav)
        with self.assertRaisesRegex(PermissionError, "role_denied"):
            self.service.request_status(viewer, self.uav)
        self.registry.unassign(self.token, self.user, self.uav)
        with self.assertRaisesRegex(PermissionError, "uav_unassigned"):
            self.service.request_status(self.token, self.uav)
        self.assertIsNone(self.dispatcher.dispatch_one())
        self.sender.assert_not_called()

    def test_changes_after_enqueue_block_sending(self):
        request = self.service.request_status(self.token, self.uav)
        self.registry.unassign(self.token, self.user, self.uav)
        self.assertEqual(self.dispatcher.dispatch_one(), "denied")
        self.assertEqual(self.service.result(self.token, request)["reason"], "uav_unassigned")
        self.registry.assign(self.token, self.user, self.uav)
        self.service.request_status(self.token, self.uav)
        self.auth.logout(self.token)
        self.assertEqual(self.dispatcher.dispatch_one(), "denied")
        self.sender.assert_not_called()

    def test_expiry_identity_mismatch_and_transport_failure(self):
        request = self.service.request_status(self.token, self.uav)
        self.dispatcher.clock = lambda: time.time() + 31
        self.assertEqual(self.dispatcher.dispatch_one(), "denied")
        self.assertEqual(self.service.result(self.token, request)["reason"], "command_expired")
        self.dispatcher.clock = time.time
        self.service.request_status(self.token, self.uav)
        self.dispatcher.signing_key_id = "b" * 64
        self.assertEqual(self.dispatcher.dispatch_one(), "denied")
        self.sender.assert_not_called()
        self.dispatcher.signing_key_id = "a" * 64
        request = self.service.request_status(self.token, self.uav)
        self.sender.side_effect = OSError("Test transport failure")
        self.assertEqual(self.dispatcher.dispatch_one(), "failed")
        self.assertEqual(self.service.result(self.token, request)["reason"], "transport_error")
        self.assertIsNone(self.dispatcher.dispatch_one())
        self.sender.assert_called_once()

    def test_claimed_request_is_not_retried_after_restart_and_schema_three_upgrades(self):
        request = self.service.request_status(self.token, self.uav)
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE command_requests SET status='dispatching' WHERE request_id=?", (request,))
        self.assertIsNone(self.dispatcher.dispatch_one())
        self.sender.assert_not_called()
        with closing(connect_database(self.path)) as db, db:
            db.execute("DROP TABLE communication_events")
            db.execute("DROP TABLE communication_state")
            db.execute("DROP TABLE telemetry_records")
            db.execute("DROP TABLE command_requests")
            db.execute("PRAGMA user_version=3")
        initialize_database(self.path)
        self.assertEqual(self.auth.authenticate(self.token)["user_id"], self.user)

    def test_wire_sender_only_requests_sys_status_with_signing_enabled(self):
        connection = Mock()
        connection.mavlink20.return_value = True
        sender = MAVLinkStatusSender(connection, b"x" * 32)
        sender(1)
        connection.setup_signing.assert_called_once_with(
            b"x" * 32, sign_outgoing=True, link_id=31)
        connection.mav.command_long_send.assert_called_once_with(1, 1, 512, 0, 1, 0, 0, 0, 0, 0, 0)
