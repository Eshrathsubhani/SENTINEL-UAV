"""Enforce the registry mapping for telemetry from an authenticated UAV gateway."""

from contextlib import closing
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from math import isfinite
from datetime import timedelta

from database.identity_database import connect_database, initialize_database
from database.telemetry_repository import insert_record, timestamp_us
from gateways.telemetry_record import encode_record
from database.connection import database_transaction
from database.communication_repository import expire_heartbeats, observe_heartbeat, utc_us

LOGGER = logging.getLogger(__name__)


class RegistryGuard:
    def __init__(self, database, *, heartbeat_timeout=5, clock=utc_us):
        if (type(heartbeat_timeout) not in (int, float) or not isfinite(heartbeat_timeout)
                or not 0.001 <= heartbeat_timeout <= 3600):
            raise ValueError("Heartbeat timeout must be 0.001 to 3600 seconds")
        self.timeout_us = int(heartbeat_timeout * 1000000)
        self.clock = clock
        self.database = Path(database)
        if not self.database.is_file():
            raise ValueError("The identity database must already exist")
        initialize_database(self.database)

    def __call__(self, record, peer_identity):
        encode_record(record)  # Validate the complete bounded record, including direct callers.
        if not 1 <= len(record.get("record_id", "")) <= 128:
            raise ValueError("Invalid history record ID")
        with closing(connect_database(self.database)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            uav = db.execute(
                "SELECT * FROM uavs WHERE certificate_identity = ?", (peer_identity,)
            ).fetchone()
            reason = self._reason(uav, record, peer_identity)
            now_us = self.clock()
            received_at = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=now_us)).isoformat()
            result = None
            if reason == "allowed":
                result = insert_record(db, uav["uav_id"], record, timestamp_us(received_at))
                if result == "conflict":
                    reason = "record_id_conflict"
            db.execute("""
                INSERT INTO authorization_events (actor_id, target_id, action, decision, reason)
                VALUES (?, ?, 'telemetry.ingest', ?, ?)
            """, (peer_identity, uav["uav_id"] if uav else None,
                  "allow" if reason == "allowed" else "deny", reason))
            previous = db.execute(
                "SELECT payload_json FROM telemetry_snapshots WHERE uav_id=? AND message_type=?",
                (uav["uav_id"], record["message_type"]),
            ).fetchone() if reason == "allowed" else None
            try:
                previous_capture = json.loads(previous["payload_json"]).get("captured_at") if previous else None
                previous_us = timestamp_us(previous_capture) if previous_capture else None
            except (ValueError, TypeError, OverflowError):
                previous_us = None  # A valid record may replace a corrupt legacy snapshot.
            newest = previous_us is None or timestamp_us(record["captured_at"]) >= previous_us
            if reason == "allowed" and result == "inserted" and newest:
                db.execute("""
                    INSERT INTO telemetry_snapshots VALUES (?, ?, ?, ?)
                    ON CONFLICT(uav_id, message_type) DO UPDATE SET
                        payload_json=excluded.payload_json,
                        received_at_utc=excluded.received_at_utc
                """, (uav["uav_id"], record["message_type"], json.dumps(record, allow_nan=False),
                      received_at))
            if reason == "allowed" and result == "inserted" and record["message_type"] == "HEARTBEAT":
                observe_heartbeat(db, uav, record, now_us, timestamp_us(record["captured_at"]), self.timeout_us)
        if reason != "allowed":
            LOGGER.warning("gateway_registry_denied reason=%s", reason)
            raise ValueError("Registry rejected the telemetry record")
        LOGGER.info("gateway_registry_allowed uav_id=%s", uav["uav_id"])

    def check_heartbeat_timeouts(self):
        """Trusted GCS observer task; never an unauthenticated user API."""
        with database_transaction(self.database) as db:
            expire_heartbeats(db, self.clock())

    @staticmethod
    def _reason(uav, record, peer_identity):
        if uav is None:
            return "unknown_uav"
        if uav["status"] != "active":
            return "uav_inactive"
        if record.get("schema_version") != 3:
            return "signing_attestation_required"
        if record["uav_identity"] != peer_identity:
            return "identity_mismatch"
        if record["system_id"] != uav["system_id"]:
            return "system_id_mismatch"
        if record["signing_key_id"] != uav["signing_key_id"]:
            return "signing_key_mismatch"
        return "allowed"
