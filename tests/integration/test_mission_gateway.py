"""Mission associations commit before a real loopback mTLS acknowledgement."""

import unittest

from backend.missions.mission_service import MissionService
from database.connection import database_transaction
from database.telemetry_repository import timestamp_us
from security.authentication.auth_service import _token_hash
from security.identity.gateway_registry import RegistryGuard
import test_gateway_registry as gateway_fixtures


class MissionGatewayTest(unittest.TestCase):
    def setUp(self):
        self.gateway = gateway_fixtures.GatewayRegistryTest()
        self.gateway.setUp()
        self.addCleanup(self.gateway.doCleanups)
        self.gateway.register()
        self.token = "M" * 43
        self.now = timestamp_us(self.gateway.record["captured_at"])
        self.gateway.guard = RegistryGuard(self.gateway.path, clock=lambda: self.now)
        with database_transaction(self.gateway.path) as db:
            db.execute(
                "INSERT INTO users(user_id,username,password_hash,role_name) "
                "VALUES ('operator','operator','$argon2id$fixture','Operator')"
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,'operator',0,2000000000,NULL)",
                (_token_hash(self.token),),
            )
            db.execute(
                "INSERT INTO uav_assignments(user_id,uav_id) VALUES ('operator','internal-uav-1')"
            )
        self.service = MissionService(self.gateway.path, clock=lambda: self.now)
        self.mission = self.service.create(
            self.token, "internal-uav-1", "mTLS storage trial"
        )
        self.service.transition(
            self.token, "internal-uav-1", self.mission["mission_id"], "start"
        )

    def test_real_mtls_record_is_linked_before_ack_and_remains_after_restart(self):
        received, persisted, acknowledged = self.gateway.exchange(self.gateway.record)
        self.assertTrue(acknowledged)
        self.assertEqual(received, self.gateway.record)
        self.assertEqual(persisted, [self.gateway.record])
        restarted = MissionService(self.gateway.path, clock=lambda: self.now)
        result = restarted.get(self.token, "internal-uav-1", self.mission["mission_id"])
        self.assertEqual(result["telemetry_count"], 1)
        with database_transaction(self.gateway.path, write=False) as db:
            link = db.execute(
                "SELECT record_id,mission_id FROM mission_telemetry"
            ).fetchone()
            self.assertEqual(
                tuple(link),
                (self.gateway.record["record_id"], self.mission["mission_id"]),
            )

    def test_link_storage_failure_prevents_acknowledgement_and_partial_history(self):
        with database_transaction(self.gateway.path) as db:
            db.execute(
                "CREATE TRIGGER fail_link BEFORE INSERT ON mission_telemetry BEGIN "
                "SELECT RAISE(ABORT,'injected mission association failure'); END"
            )
        self.assertEqual(self.gateway.exchange(self.gateway.record), (None, [], False))
        with database_transaction(self.gateway.path, write=False) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM mission_telemetry").fetchone()[0], 0
            )
