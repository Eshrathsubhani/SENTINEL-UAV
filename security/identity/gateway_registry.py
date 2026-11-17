"""Enforce the registry mapping for telemetry from an authenticated UAV gateway."""

from contextlib import closing
import logging
from pathlib import Path

from database.identity_database import connect_database

LOGGER = logging.getLogger(__name__)


class RegistryGuard:
    def __init__(self, database):
        self.database = Path(database)
        if not self.database.is_file():
            raise ValueError("The identity database must already exist")

    def __call__(self, record, peer_identity):
        with closing(connect_database(self.database)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            uav = db.execute(
                "SELECT * FROM uavs WHERE certificate_identity = ?", (peer_identity,)
            ).fetchone()
            reason = self._reason(uav, record, peer_identity)
            db.execute("""
                INSERT INTO authorization_events (actor_id, target_id, action, decision, reason)
                VALUES (?, ?, 'telemetry.ingest', ?, ?)
            """, (peer_identity, uav["uav_id"] if uav else None,
                  "allow" if reason == "allowed" else "deny", reason))
        if reason != "allowed":
            LOGGER.warning("gateway_registry_denied reason=%s", reason)
            raise ValueError("Registry rejected the telemetry record")
        LOGGER.info("gateway_registry_allowed uav_id=%s", uav["uav_id"])

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
