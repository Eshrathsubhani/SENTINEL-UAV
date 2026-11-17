"""Authorize and dispatch a single allowlisted local SITL status request."""

import argparse
from contextlib import closing
from getpass import getpass
import logging
from pathlib import Path
import time
from uuid import uuid4

from database.identity_database import connect_database
from security.authentication.auth_service import AuthenticationError, _principal, _token_hash
from security.authorization.policy_engine import PolicyEngine

LOGGER = logging.getLogger(__name__)
ACTION = "command.status"


def _reason(db, token_hash, uav_id, now):
    try:
        user = _principal(db, token_hash, now)
    except AuthenticationError:
        return None, "invalid_session"
    return user["user_id"], PolicyEngine._reason(db, user, uav_id, ACTION)


def _audit(db, actor, uav_id, action, allowed, reason):
    db.execute("""
        INSERT INTO authorization_events (actor_id, target_id, action, decision, reason)
        VALUES (?, ?, ?, ?, ?)
    """, (actor, uav_id, action, "allow" if allowed else "deny", reason))


class CommandService:
    def __init__(self, database):
        self.policy = PolicyEngine(database)

    def request_status(self, token, uav_id):
        if not isinstance(uav_id, str) or not 1 <= len(uav_id) <= 128:
            raise ValueError("Invalid UAV ID")
        token_hash = _token_hash(token)
        now = int(self.policy.auth.clock())
        request_id = uuid4().hex
        with self.policy.auth._transaction() as db:
            actor, reason = _reason(db, token_hash, uav_id, now)
            _audit(db, actor, uav_id, ACTION, reason == "allowed", reason)
            if reason == "allowed":
                db.execute("""
                    INSERT INTO command_requests VALUES (?, ?, ?, ?, ?, ?, 'queued', 'allowed')
                """, (request_id, token_hash, uav_id, ACTION, now, now + 30))
        if reason != "allowed":
            raise PermissionError(reason)
        return request_id

    def result(self, token, request_id):
        token_hash = _token_hash(token)
        with closing(connect_database(self.policy.auth.database)) as db:
            _principal(db, token_hash, int(self.policy.auth.clock()))
            row = db.execute(
                "SELECT status, reason FROM command_requests WHERE request_id=? AND token_hash=?",
                (request_id, token_hash),
            ).fetchone()
            if row is None:
                raise PermissionError("Unknown command request for this session")
            return dict(row)


class StatusDispatcher:
    def __init__(self, database, *, system_id, identity, signing_key_id, sender, clock=time.time):
        self.service = CommandService(database)
        self.system_id = system_id
        self.identity = identity
        self.signing_key_id = signing_key_id
        self.sender = sender
        self.clock = clock

    def dispatch_one(self):
        # Commit a claim before the external send. A crash leaves dispatching,
        # which is never retried automatically.
        with self.service.policy.auth._transaction() as db:
            request = db.execute("""
                SELECT q.* FROM command_requests q JOIN uavs u ON u.uav_id=q.uav_id
                WHERE q.status='queued' AND u.system_id=? ORDER BY q.created_at_epoch, q.request_id
                LIMIT 1
            """, (self.system_id,)).fetchone()
            if request is None:
                return None
            db.execute("UPDATE command_requests SET status='dispatching' WHERE request_id=?",
                       (request["request_id"],))

        with self.service.policy.auth._transaction() as db:
            now = int(self.clock())
            actor, reason = _reason(db, request["token_hash"], request["uav_id"], now)
            uav = db.execute("SELECT * FROM uavs WHERE uav_id=?", (request["uav_id"],)).fetchone()
            if reason == "allowed" and now >= request["expires_at_epoch"]:
                reason = "command_expired"
            if reason == "allowed" and (
                uav["system_id"] != self.system_id or uav["certificate_identity"] != self.identity
                or uav["signing_key_id"] != self.signing_key_id
            ):
                reason = "gateway_identity_mismatch"
            status = "denied"
            if reason == "allowed":
                try:
                    self.sender(self.system_id)
                except (OSError, ValueError):
                    status, reason = "failed", "transport_error"
                else:
                    status, reason = "sent", "transport_write_completed"
            _audit(db, actor, request["uav_id"], "command.status.dispatch",
                   status == "sent", reason)
            db.execute("UPDATE command_requests SET status=?, reason=? WHERE request_id=?",
                       (status, reason, request["request_id"]))
        LOGGER.info("command_status_result request_id=%s status=%s reason=%s",
                    request["request_id"], status, reason)
        return status


class MAVLinkStatusSender:
    """Send only MAV_CMD_REQUEST_MESSAGE for SYS_STATUS through the local receiver."""

    def __init__(self, connection, key):
        if not connection.mavlink20():
            raise ValueError("Status dispatch requires MAVLink 2")
        connection.mav.srcSystem = 254
        connection.mav.srcComponent = 191
        connection.setup_signing(key, sign_outgoing=True, link_id=31)
        self.connection = connection

    def __call__(self, system_id):
        # MAV_CMD_REQUEST_MESSAGE=512, MAVLINK_MSG_ID_SYS_STATUS=1.
        self.connection.mav.command_long_send(system_id, 1, 512, 0, 1, 0, 0, 0, 0, 0, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--uav-id", required=True)
    args = parser.parse_args()
    service = CommandService(args.database)
    token = None
    try:
        token = service.policy.auth.login(args.username, getpass("Account password: "))
        request_id = service.request_status(token, args.uav_id)
        print(f"Status request queued with ID {request_id}", flush=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = service.result(token, request_id)
            if result["status"] in ("sent", "denied", "failed"):
                print(f"Status request {result['status']} reason={result['reason']}")
                return 0 if result["status"] == "sent" else 1
            time.sleep(0.2)
        print("Status request timed out waiting for the gateway")
        return 1
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + "\n")
    finally:
        if token is not None:
            service.policy.auth.logout(token)


if __name__ == "__main__":
    raise SystemExit(main())
