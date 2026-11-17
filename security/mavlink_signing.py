"""Verify signed MAVLink 2 telemetry and retain replay state across restarts."""

from hashlib import sha256
from hmac import compare_digest
import logging
import sqlite3
from time import time_ns

LOGGER = logging.getLogger(__name__)
MAVLINK_EPOCH_NS = 1_420_070_400 * 1_000_000_000
SIGNING_WINDOW_TICKS = 60 * 100_000
TELEMETRY_TYPES = {"HEARTBEAT", "GLOBAL_POSITION_INT"}


class SigningVerifier:
    """Keep a durable timestamp watermark per credential and MAVLink stream."""

    def __init__(self, key, state_path):
        if len(key) != 32:
            raise ValueError("A MAVLink signing key must contain exactly 32 raw bytes")
        self.key = key
        self.key_id = sha256(key).hexdigest()
        self.db = sqlite3.connect(state_path)
        try:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS stream_watermarks (
                    key_id TEXT, system_id INTEGER, component_id INTEGER, link_id INTEGER,
                    timestamp INTEGER NOT NULL,
                    PRIMARY KEY (key_id, system_id, component_id, link_id)
                )
            """)
        except sqlite3.Error:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def verify(self, frame):
        """Return a rejection category, or None after committing an accepted frame."""
        if len(frame) < 12 or frame[0] != 0xFD or not frame[2] & 1:
            return "unsigned"
        if len(frame) != 10 + frame[1] + 2 + 13:
            return "invalid_frame_length"

        expected = sha256(self.key + frame[:-6]).digest()[:6]
        if not compare_digest(expected, frame[-6:]):
            return "invalid_signature"

        timestamp = int.from_bytes(frame[-12:-6], "little")
        now = (time_ns() - MAVLINK_EPOCH_NS) // 10_000
        if abs(now - timestamp) > SIGNING_WINDOW_TICKS:
            return "timestamp_outside_window"

        with self.db:
            update = self.db.execute("""
                INSERT INTO stream_watermarks VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (key_id, system_id, component_id, link_id)
                DO UPDATE SET timestamp = excluded.timestamp
                WHERE excluded.timestamp > stream_watermarks.timestamp
            """, (self.key_id, frame[5], frame[6], frame[-13], timestamp))
        return None if update.rowcount else "replay_or_out_of_order"


class SignedTelemetryReceiver:
    """Filter live telemetry before the collector writes or forwards it."""

    def __init__(self, receiver, verifier, system_id):
        self.receiver = receiver
        self.verifier = verifier
        self.system_id = system_id
        self.rejected = {}
        self.accepted = 0

    def recv_match(self, **kwargs):
        message = self.receiver.recv_match(**kwargs)
        if message is None:
            return None
        if (message.get_type() not in TELEMETRY_TYPES
                or message.get_srcSystem() != self.system_id
                or message.get_srcComponent() != 1):
            return None
        reason = self.verifier.verify(bytes(message.get_msgbuf()))
        if reason is not None:
            self.rejected[reason] = self.rejected.get(reason, 0) + 1
            if self.rejected[reason] == 1:
                LOGGER.warning("mavlink_rejected category=%s system_id=%d", reason, self.system_id)
            return None
        self.accepted += 1
        return message

    def close(self):
        try:
            self.receiver.close()
        finally:
            self.verifier.close()
            LOGGER.info("mavlink_signing_summary accepted=%d rejected=%s",
                        self.accepted, self.rejected)
