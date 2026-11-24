"""Real loopback TLS event persistence and refusal when event storage fails."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from database.connection import database_transaction
from database.identity_database import initialize_database
from gateways.gcs_gateway import open_listener, receive_telemetry
from gateways.uav_gateway import send_telemetry
from security.event_sink import SecurityEventSink
from security.tls_context import client_context, server_context
from test_gateway_mtls import issue_certificate

IDENTITY = "urn:sentinel:uav:1"
SERVER = "gcs.sentinel.test"
RECORD = {
    "schema_version": 1,
    "vehicle_id": "1",
    "message_type": "SYNTHETIC_POSITION",
    "captured_at": "2026-01-01T00:00:00Z",
    "values": {"relative_altitude_m": 1},
}


class GatewaySecurityEventTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "identity.sqlite3"
        initialize_database(self.path)
        self.sink = SecurityEventSink(self.path, "gcs_gateway")
        self.ca = issue_certificate("Event test CA")
        self.ca_file = self.root / "ca.pem"
        self.ca_file.write_bytes(self.ca[0].public_bytes(serialization.Encoding.PEM))
        self.server = server_context(
            **self.credentials(
                "server", x509.DNSName(SERVER), ExtendedKeyUsageOID.SERVER_AUTH
            )
        )
        self.client = client_context(
            **self.credentials(
                "client",
                x509.UniformResourceIdentifier(IDENTITY),
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
        )

    def credentials(self, name, identity, purpose):
        cert, key = issue_certificate(
            name, issuer=self.ca, identity=identity, purpose=purpose
        )
        cert_file, key_file = self.root / (name + ".pem"), self.root / (name + ".key")
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return dict(ca_file=self.ca_file, cert_file=cert_file, key_file=key_file)

    def exchange(self, client=None, sink=None, **options):
        with open_listener() as listener, ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                receive_telemetry,
                listener,
                self.server,
                IDENTITY,
                timeout=1.5,
                on_event=sink or self.sink,
                **options,
            )
            client_error = None
            try:
                send_telemetry(
                    client or self.client,
                    listener.getsockname()[1],
                    SERVER,
                    RECORD,
                    timeout=2,
                )
            except (OSError, ValueError) as error:
                client_error = error
            return future.result(timeout=5), client_error

    def events(self):
        with database_transaction(self.path, write=False) as db:
            return [
                dict(r)
                for r in db.execute("SELECT * FROM security_events ORDER BY event_id")
            ]

    def test_valid_mutual_tls_records_open_and_authenticated_peer(self):
        result, error = self.exchange()
        self.assertEqual(result, RECORD)
        self.assertIsNone(error)
        self.assertEqual(
            [r["event"] for r in self.events()],
            ["connection_opened", "peer_authenticated"],
        )
        self.assertIn("TLSv1.3", self.events()[1]["details_json"])

    def test_missing_certificate_records_handshake_denial(self):
        client = ssl.create_default_context(cafile=self.ca_file)
        result, error = self.exchange(client)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual(self.events()[-1]["event"], "handshake_failed")
        self.assertEqual(self.events()[-1]["outcome"], "deny")

    def test_wrong_identity_records_denial(self):
        wrong = client_context(
            **self.credentials(
                "other",
                x509.UniformResourceIdentifier("urn:other"),
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
        )
        result, error = self.exchange(wrong)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual(self.events()[-1]["event"], "peer_identity_rejected")

    def test_registry_rejection_is_audited_and_not_acknowledged(self):
        def denied(record, identity):
            raise ValueError("Unregistered identity")

        result, error = self.exchange(record_guard=denied)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual(self.events()[-1]["event"], "telemetry_rejected")

    def test_evidence_write_failure_records_storage_event_and_no_acknowledgement(self):
        def unavailable(record):
            raise OSError("private filesystem path")

        result, error = self.exchange(on_record=unavailable)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        event = self.events()[-1]
        self.assertEqual(
            (event["category"], event["event"]), ("storage", "evidence_write_failed")
        )
        self.assertNotIn("private filesystem path", event["details_json"])

    def test_event_storage_failure_refuses_record_before_persistence(self):
        saved = []

        def broken_sink(category, event, **metadata):
            if event == "peer_authenticated":
                raise OSError("event database unavailable")
            self.sink(category, event, **metadata)

        with self.assertRaisesRegex(OSError, "event database unavailable"):
            self.exchange(sink=broken_sink, on_record=saved.append)
        self.assertEqual(saved, [])
