"""Loopback TLS checks using ephemeral certificate authorities."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gateways.gcs_gateway import open_listener, receive_telemetry
from gateways.uav_gateway import send_telemetry
from gateways.live_gateway import live_record, record_credential_config
from security.tls_context import client_context, server_context

SERVER_NAME = "gcs.sentinel.test"
UAV_IDENTITY = "urn:sentinel:uav:1"
NOW = datetime.now(timezone.utc)
RECORD = {
    "schema_version": 1,
    "vehicle_id": "1",
    "message_type": "SYNTHETIC_POSITION",
    "captured_at": "2026-01-01T00:00:00+00:00",
    "values": {"relative_altitude_m": 5.0},
}


def issue_certificate(name, *, issuer=None, identity=None, purpose=None, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_cert, signing_key = issuer or (None, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=2))
        .not_valid_after(NOW + timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
    )
    if identity is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([identity]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
    return builder.sign(signing_key, hashes.SHA256()), key


class GatewayMTLSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name)

    def setUp(self):
        ca = issue_certificate("Trusted test CA")
        self.ca_file = self.root / "ca.pem"
        self.ca_file.write_bytes(ca[0].public_bytes(serialization.Encoding.PEM))
        self.ca = ca
        self.server = server_context(**self.credentials(
            "server", ca, x509.DNSName(SERVER_NAME), ExtendedKeyUsageOID.SERVER_AUTH,
        ))

    def credentials(self, name, issuer, identity, purpose, *, expired=False):
        cert, key = issue_certificate(name, issuer=issuer, identity=identity,
                                      purpose=purpose, expired=expired)
        cert_file = self.root / f"{name}.pem"
        key_file = self.root / f"{name}.key"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, "wb", opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
            output.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return dict(ca_file=str(self.ca_file), cert_file=str(cert_file), key_file=str(key_file))

    def run_exchange(self, client, *, server_name=SERVER_NAME):
        with open_listener() as listener, ThreadPoolExecutor(max_workers=1) as executor:
            bound_port = listener.getsockname()[1]
            future = executor.submit(receive_telemetry, listener, self.server, UAV_IDENTITY)
            client_error = None
            try:
                send_telemetry(client, bound_port, server_name, RECORD)
            except OSError as error:
                client_error = error
            return future.result(timeout=7), client_error

    def make_client(self, *, issuer=None, identity=UAV_IDENTITY, expired=False):
        return client_context(**self.credentials(
            "client", issuer or self.ca, x509.UniformResourceIdentifier(identity),
            ExtendedKeyUsageOID.CLIENT_AUTH, expired=expired,
        ))

    def test_authorized_uav_delivers_one_record_over_tls13(self):
        with self.assertLogs("gateways.gcs_gateway", level="INFO") as audit:
            received, client_error = self.run_exchange(self.make_client())
        self.assertEqual(received, RECORD, f"client={client_error!r}; server={audit.output}")
        self.assertIsNone(client_error)
        self.assertIn("tls_version=TLSv1.3", audit.output[0])

    def test_missing_certificate_delivers_no_records(self):
        client = ssl.create_default_context(cafile=str(self.ca_file))
        received, _ = self.run_exchange(client)
        self.assertIsNone(received)

    def test_untrusted_expired_and_wrong_identity_deliver_no_records(self):
        cases = {
            "untrusted": {"issuer": issue_certificate("Other test CA")},
            "expired": {"expired": True},
            "wrong identity": {"identity": "urn:sentinel:uav:2"},
        }
        for name, options in cases.items():
            with self.subTest(name=name):
                received, _ = self.run_exchange(self.make_client(**options))
                self.assertIsNone(received)

    def test_live_records_are_validated_and_persisted_before_ack(self):
        heartbeat = SimpleNamespace(
            get_type=lambda: "HEARTBEAT", get_srcSystem=lambda: 1,
            get_srcComponent=lambda: 1, type=2, base_mode=128,
        )
        position = SimpleNamespace(
            get_type=lambda: "GLOBAL_POSITION_INT", get_srcSystem=lambda: 1,
            get_srcComponent=lambda: 1, lat=-353632622, lon=1491652375,
            alt=584000, relative_alt=5000, hdg=65535,
            vx=110, vy=-220, vz=30, time_boot_ms=1234,
        )
        records = [live_record(message, RECORD["captured_at"], UAV_IDENTITY)
                   for message in (heartbeat, position)]
        self.assertEqual(records[0]["values"]["armed"], 1)
        self.assertEqual(records[1]["values"]["velocity_east_mps"], -2.2)
        self.assertEqual(records[1]["source_boot_ms"], 1234)
        recorded = []
        client = self.make_client()
        with open_listener() as listener, ThreadPoolExecutor(max_workers=1) as executor:
            port = listener.getsockname()[1]
            for record in records:
                future = executor.submit(receive_telemetry, listener, self.server, UAV_IDENTITY,
                                         on_record=recorded.append, required_schema=2)
                send_telemetry(client, port, SERVER_NAME, record)
                self.assertEqual(future.result(timeout=7), record)
            invalid = dict(records[0], uav_identity="urn:sentinel:uav:2")
            future = executor.submit(receive_telemetry, listener, self.server, UAV_IDENTITY,
                                     on_record=recorded.append, required_schema=2)
            with self.assertRaises(OSError):
                send_telemetry(client, port, SERVER_NAME, invalid)
            self.assertIsNone(future.result(timeout=7))
        self.assertEqual(recorded, records)

    def test_rotated_ca_accepts_reissued_client_and_rejects_retired_client(self):
        retired_ca = self.ca
        audit_db = self.root / "rotation-audit.sqlite3"
        audit_config = SimpleNamespace(
            role="gcs", credential_audit_db=audit_db, ca_file=self.ca_file,
            cert_file=self.root / "server.pem",
        )
        with self.assertLogs("security.credential_audit") as audit:
            record_credential_config(audit_config)
            self.ca = issue_certificate("Replacement test CA")
            self.ca_file.write_bytes(self.ca[0].public_bytes(serialization.Encoding.PEM))
            replacement = self.credentials(
                "server-rotated", self.ca, x509.DNSName(SERVER_NAME),
                ExtendedKeyUsageOID.SERVER_AUTH,
            )
            self.server = server_context(**replacement)
            audit_config.cert_file = replacement["cert_file"]
            record_credential_config(audit_config)
        for kind in ("tls_certificate", "tls_trust_bundle"):
            self.assertTrue(any(f"credential_retired role=gcs kind={kind}" in line
                                for line in audit.output))
            self.assertTrue(any(f"credential_rotated role=gcs kind={kind}" in line
                                for line in audit.output))
        received, client_error = self.run_exchange(self.make_client())
        self.assertEqual(received, RECORD)
        self.assertIsNone(client_error)
        received, _ = self.run_exchange(self.make_client(issuer=retired_ca))
        self.assertIsNone(received)

    def test_wrong_server_name_delivers_no_records(self):
        received, client_error = self.run_exchange(
            self.make_client(), server_name="wrong.sentinel.test",
        )
        self.assertIsNone(received)
        self.assertIsInstance(client_error, ssl.SSLCertVerificationError)

    def test_client_can_connect_to_a_restarted_listener(self):
        client = self.make_client()
        received, client_error = self.run_exchange(client)
        self.assertEqual(received, RECORD)
        self.assertIsNone(client_error)
        received, client_error = self.run_exchange(client)
        self.assertEqual(received, RECORD)
        self.assertIsNone(client_error)
