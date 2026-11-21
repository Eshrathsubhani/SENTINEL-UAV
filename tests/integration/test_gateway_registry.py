"""mTLS acceptance and registry rejection through the normal GCS entry point."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from database.identity_database import connect_database, initialize_database
from gateways.gcs_gateway import open_listener, receive_telemetry
from gateways.live_gateway import live_record
from gateways.uav_gateway import send_telemetry
from security.identity.gateway_registry import RegistryGuard
from security.tls_context import client_context, server_context
from test_gateway_mtls import issue_certificate

SERVER_NAME = "gcs.sentinel.test"
IDENTITY = "urn:sentinel:uav:1"


class GatewayRegistryTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "identity.sqlite3"
        initialize_database(self.path)
        self.guard = RegistryGuard(self.path)
        self.ca = issue_certificate("Registry test CA")
        from cryptography.hazmat.primitives import serialization
        self.encoding = serialization.Encoding.PEM
        self.serialization = serialization
        self.ca_file = self.root / "ca.pem"
        self.ca_file.write_bytes(self.ca[0].public_bytes(self.encoding))
        self.server = server_context(**self.credentials(
            "gcs", x509.DNSName(SERVER_NAME), ExtendedKeyUsageOID.SERVER_AUTH))
        self.client = client_context(**self.credentials(
            "uav", x509.UniformResourceIdentifier(IDENTITY), ExtendedKeyUsageOID.CLIENT_AUTH))
        heartbeat = SimpleNamespace(get_type=lambda: "HEARTBEAT", get_srcSystem=lambda: 1,
                                    get_srcComponent=lambda: 1, type=2, base_mode=0)
        self.record = live_record(heartbeat, "2026-11-18T00:00:00+00:00", IDENTITY, "a" * 64)

    def credentials(self, name, identity, purpose):
        cert, key = issue_certificate(name, issuer=self.ca, identity=identity, purpose=purpose)
        cert_file = self.root / (name + ".pem")
        key_file = self.root / (name + ".key")
        cert_file.write_bytes(cert.public_bytes(self.encoding))
        key_file.write_bytes(key.private_bytes(
            self.encoding, self.serialization.PrivateFormat.PKCS8,
            self.serialization.NoEncryption()))
        return dict(ca_file=str(self.ca_file), cert_file=str(cert_file), key_file=str(key_file))

    def register(self):
        with closing(connect_database(self.path)) as db, db:
            db.execute("""
                INSERT INTO uavs
                (uav_id, name, system_id, certificate_identity, signing_key_id, status)
                VALUES ('internal-uav-1', 'SITL', 1, ?, ?, 'active')
            """, (IDENTITY, "a" * 64))

    def exchange(self, record):
        persisted = []
        with open_listener() as listener, ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(receive_telemetry, listener, self.server, IDENTITY,
                                 on_record=persisted.append, required_schema=3,
                                 record_guard=self.guard)
            acknowledged = True
            try:
                send_telemetry(self.client, listener.getsockname()[1], SERVER_NAME, record)
            except (OSError, ValueError):
                acknowledged = False
            received = future.result(timeout=7)
        return received, persisted, acknowledged

    def test_registered_record_is_persisted_and_acknowledged(self):
        self.register()
        received, persisted, acknowledged = self.exchange(self.record)
        self.assertEqual(received, self.record)
        self.assertEqual(persisted, [self.record])
        self.assertTrue(acknowledged)

    def test_unknown_and_revoked_uav_are_not_persisted_or_acknowledged(self):
        self.assertEqual(self.exchange(self.record), (None, [], False))
        self.register()
        self.assertTrue(self.exchange(self.record)[2])
        with closing(connect_database(self.path)) as db, db:
            db.execute("UPDATE uavs SET status = 'revoked'")
        self.assertEqual(self.exchange(self.record), (None, [], False))
        with closing(connect_database(self.path)) as db:
            reasons = [row[0] for row in db.execute(
                "SELECT reason FROM authorization_events ORDER BY event_id")]
        self.assertEqual(reasons, ["unknown_uav", "allowed", "uav_inactive"])

    def test_wrong_system_and_signing_key_are_rejected(self):
        self.register()
        wrong_system = dict(self.record, system_id=2, vehicle_id="2")
        self.assertEqual(self.exchange(wrong_system), (None, [], False))
        wrong_key = dict(self.record, signing_key_id="b" * 64)
        self.assertEqual(self.exchange(wrong_key), (None, [], False))
        with closing(connect_database(self.path)) as db:
            reasons = {row[0] for row in db.execute("SELECT reason FROM authorization_events")}
        self.assertEqual(reasons, {"system_id_mismatch", "signing_key_mismatch"})

    def test_legacy_record_cannot_enter_registry_protected_listener(self):
        self.register()
        legacy = dict(self.record, schema_version=2)
        del legacy["signing_key_id"]
        self.assertEqual(self.exchange(legacy), (None, [], False))

    def test_database_failure_is_not_acknowledged_and_leaves_no_history(self):
        self.register()
        with closing(connect_database(self.path)) as db, db:
            db.execute("CREATE TRIGGER fail_history BEFORE INSERT ON telemetry_records "
                       "BEGIN SELECT RAISE(ABORT,'injected storage failure'); END")
        self.assertEqual(self.exchange(self.record), (None, [], False))
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_snapshots").fetchone()[0], 0)

    def test_battery_records_cross_mtls_and_are_stored_before_acknowledgement(self):
        self.register()
        status = SimpleNamespace(get_type=lambda: "SYS_STATUS", get_srcSystem=lambda: 1,
                                 get_srcComponent=lambda: 1, battery_remaining=75, voltage_battery=12000)
        battery = SimpleNamespace(get_type=lambda: "BATTERY_STATUS", get_srcSystem=lambda: 1,
                                  get_srcComponent=lambda: 1, id=0, battery_remaining=75,
                                  voltages=[12000] + [65535] * 9, voltages_ext=[0] * 4)
        for msg in (status, battery):
            with self.subTest(message_type=msg.get_type()):
                record = live_record(msg, "2026-11-18T00:00:00+00:00", IDENTITY, "a" * 64)
                received, persisted, acknowledged = self.exchange(record)
                self.assertEqual(received, record)
                self.assertEqual(persisted, [record])
                self.assertTrue(acknowledged)
                with closing(connect_database(self.path)) as db:
                    row = db.execute("SELECT payload_json FROM telemetry_records WHERE record_id=?",
                                     (record["record_id"],)).fetchone()
                    import json
                    self.assertEqual(json.loads(row["payload_json"]), record)

    def test_accepted_mtls_heartbeat_records_communication_evidence(self):
        from database.telemetry_repository import timestamp_us
        self.register()
        self.guard = RegistryGuard(self.path, clock=lambda: timestamp_us(self.record["captured_at"]))
        self.assertTrue(self.exchange(self.record)[2])
        with closing(connect_database(self.path)) as db:
            state = db.execute("SELECT state FROM communication_state").fetchone()[0]
            event = db.execute("SELECT event,record_id FROM communication_events").fetchone()
            self.assertEqual(state, "connected")
            self.assertEqual(tuple(event), ("heartbeat_received", self.record["record_id"]))

    def test_communication_storage_failure_sends_no_success_acknowledgement(self):
        from database.telemetry_repository import timestamp_us
        self.register()
        self.guard = RegistryGuard(self.path, clock=lambda: timestamp_us(self.record["captured_at"]))
        with closing(connect_database(self.path)) as db, db:
            db.execute("CREATE TRIGGER fail_communication BEFORE INSERT ON communication_events "
                       "BEGIN SELECT RAISE(ABORT,'injected event failure'); END")
        self.assertEqual(self.exchange(self.record), (None, [], False))
        with closing(connect_database(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_records").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry_snapshots").fetchone()[0], 0)
