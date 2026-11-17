"""Validate strict receive-side signing policy with local protocol fixtures."""

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from security.mavlink_signing import MAVLINK_EPOCH_NS, SignedTelemetryReceiver, SigningVerifier

KEY = bytes(range(32))
ROTATED_KEY = bytes(reversed(KEY))
NOW_TICKS = 100_000_000


def accepted_parser_fixture(timestamp, key=KEY):
    # The verifier receives a parsed frame from pymavlink. CRC checking
    # is outside this unit fixture and covered by the real-parser test.
    header = bytes.fromhex("fd090100000101000000")
    payload_and_crc = bytes(11)
    trailer = b"\x01" + timestamp.to_bytes(6, "little")
    raw = header + payload_and_crc + trailer
    return raw + sha256(key + raw).digest()[:6]


class MAVLinkSigningTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state_path = Path(directory.name) / "replay.sqlite3"
        clock = patch("security.mavlink_signing.time_ns",
                      return_value=MAVLINK_EPOCH_NS + NOW_TICKS * 10_000)
        self.addCleanup(clock.stop)
        clock.start()

    def open_verifier(self, key=KEY):
        verifier = SigningVerifier(key, self.state_path)
        self.addCleanup(verifier.close)
        return verifier

    def test_rejects_unsigned_wrong_key_and_modified_frames(self):
        verifier = self.open_verifier()
        valid = accepted_parser_fixture(NOW_TICKS)
        modified = valid[:-1] + bytes([valid[-1] ^ 1])
        unsigned = bytes.fromhex("fd090000000101000000") + bytes(11)
        self.assertEqual(verifier.verify(unsigned), "unsigned")
        self.assertEqual(verifier.verify(modified), "invalid_signature")
        self.assertEqual(verifier.verify(accepted_parser_fixture(NOW_TICKS, ROTATED_KEY)),
                         "invalid_signature")
        self.assertIsNone(verifier.verify(valid))

    def test_rejects_stale_duplicate_and_out_of_order_across_restart(self):
        first = accepted_parser_fixture(NOW_TICKS)
        verifier = self.open_verifier()
        self.assertIsNone(verifier.verify(first))
        second = self.open_verifier()
        self.assertEqual(second.verify(first), "replay_or_out_of_order")
        self.assertEqual(second.verify(accepted_parser_fixture(NOW_TICKS - 1)),
                         "replay_or_out_of_order")
        for timestamp in (NOW_TICKS - 6_000_001, NOW_TICKS + 6_000_001):
            self.assertEqual(second.verify(accepted_parser_fixture(timestamp)),
                             "timestamp_outside_window")
        self.assertIsNone(second.verify(accepted_parser_fixture(NOW_TICKS + 1)))

    def test_rotation_rejects_retired_key(self):
        self.assertIsNone(self.open_verifier().verify(accepted_parser_fixture(NOW_TICKS)))
        rotated = self.open_verifier(ROTATED_KEY)
        self.assertEqual(rotated.verify(accepted_parser_fixture(NOW_TICKS)), "invalid_signature")
        self.assertIsNone(rotated.verify(accepted_parser_fixture(NOW_TICKS, ROTATED_KEY)))

    def test_receiver_delivers_a_signed_message_once(self):
        frame = accepted_parser_fixture(NOW_TICKS)
        message = SimpleNamespace(get_type=lambda: "HEARTBEAT", get_srcSystem=lambda: 1,
                                  get_srcComponent=lambda: 1, get_msgbuf=lambda: frame)
        raw = Mock()
        raw.recv_match.return_value = message
        receiver = SignedTelemetryReceiver(raw, self.open_verifier(), 1)
        self.assertIs(receiver.recv_match(), message)
        with self.assertLogs("security.mavlink_signing", level="WARNING") as audit:
            self.assertIsNone(receiver.recv_match())
        self.assertIn("replay_or_out_of_order", audit.output[0])

    def test_pymavlink_signed_heartbeat_retains_the_original_frame(self):
        try:
            from pymavlink.dialects.v20 import ardupilotmega
        except ImportError:
            self.skipTest("pymavlink is required for the parser compatibility test")
        encoder = ardupilotmega.MAVLink(None, srcSystem=1, srcComponent=1)
        encoder.signing.secret_key = KEY
        encoder.signing.timestamp = NOW_TICKS
        encoder.signing.link_id = 1
        encoder.signing.sign_outgoing = True
        frame = encoder.heartbeat_encode(2, 3, 0, 0, 3).pack(encoder)
        decoder = ardupilotmega.MAVLink(None)
        parsed = decoder.parse_char(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(bytes(parsed.get_msgbuf()), frame)
        self.assertIsNone(self.open_verifier().verify(bytes(parsed.get_msgbuf())))
