"""Authorize UAV resource access using current sessions, roles, and assignments."""

import argparse
from dataclasses import dataclass
from getpass import getpass
import json
from pathlib import Path

from security.authorization.mission_policy import mission_reason, valid_coordinates
from security.authentication.auth_service import AuthService, AuthenticationError, _principal, _token_hash

ACTIONS = {
    "telemetry.read": "telemetry.read",
    "status.read": "status.read",
    "command.rtl": "command.request",
    "mission.update": "command.request",
    "mission.configure": "policies.manage",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    user_id: str | None
    uav_id: str | None
    action: str


class PolicyEngine:
    """Evaluate and audit a decision within a single database transaction."""

    def __init__(self, database):
        self.auth = AuthService(database)

    def authorize(self, token, uav_id, action):
        decision, _ = self._request(token, uav_id, action)
        return decision

    def read_telemetry(self, token, uav_id):
        decision, result = self._request(token, uav_id, "telemetry.read", read=True)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        return result

    def configure_mission(self, token, uav_id, latitude, longitude):
        if not valid_coordinates(latitude, longitude):
            raise ValueError("Invalid mission origin coordinates")
        decision, _ = self._request(token, uav_id, "mission.configure",
                                    origin=(latitude, longitude))
        if not decision.allowed:
            raise PermissionError(decision.reason)
        return decision

    def _request(self, token, uav_id, action, *, read=False, origin=None):
        resource = uav_id if isinstance(uav_id, str) and 1 <= len(uav_id) <= 128 else None
        action = action if isinstance(action, str) and 1 <= len(action) <= 128 else "invalid_action"
        result = None
        with self.auth._transaction() as db:
            user = None
            try:
                user = _principal(db, _token_hash(token), int(self.auth.clock()))
            except AuthenticationError:
                reason = "invalid_session"
            else:
                reason = self._reason(db, user, resource, action)
                if reason == "allowed" and action == "mission.update":
                    reason = mission_reason(db, resource, float(self.auth.clock()))
            decision = Decision(
                reason == "allowed", reason, user["user_id"] if user else None, resource, action
            )
            db.execute("""
                INSERT INTO authorization_events (actor_id, target_id, action, decision, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (decision.user_id, resource, action,
                  "allow" if decision.allowed else "deny", reason))
            if decision.allowed and origin is not None:
                configuration = json.dumps({
                    "origin_latitude_deg": origin[0], "origin_longitude_deg": origin[1],
                })
                db.execute("""
                    INSERT INTO policies (name, configuration_json, version) VALUES (?, ?, 1)
                    ON CONFLICT(name) DO UPDATE SET configuration_json=excluded.configuration_json,
                        version=policies.version + 1, updated_at=CURRENT_TIMESTAMP
                """, ("mission_area:" + resource, configuration))
            if decision.allowed and read:
                result = [
                    {"received_at_utc": row["received_at_utc"],
                     "record": json.loads(row["payload_json"])}
                    for row in db.execute(
                        "SELECT * FROM telemetry_snapshots WHERE uav_id = ? ORDER BY message_type",
                        (resource,),
                    )
                ]
        return decision, result

    @staticmethod
    def _reason(db, user, uav_id, action):
        permission = ACTIONS.get(action)
        if permission is None:
            return "unsupported_action"
        allowed = db.execute("""
            SELECT 1 FROM role_permissions WHERE role_name = ? AND permission_name = ?
        """, (user["role_name"], permission)).fetchone()
        if allowed is None:
            return "role_denied"
        uav = db.execute("SELECT status FROM uavs WHERE uav_id = ?", (uav_id,)).fetchone()
        if uav is None:
            return "unknown_uav"
        if uav["status"] != "active":
            return "uav_inactive"
        assignment = db.execute(
            "SELECT 1 FROM uav_assignments WHERE user_id = ? AND uav_id = ?",
            (user["user_id"], uav_id),
        ).fetchone()
        if assignment is None:
            return "uav_unassigned"
        return "allowed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--uav-id", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--read-telemetry", action="store_true")
    parser.add_argument("--origin-latitude", type=float)
    parser.add_argument("--origin-longitude", type=float)
    args = parser.parse_args()
    if args.read_telemetry and args.action != "telemetry.read":
        parser.error("--read-telemetry requires --action telemetry.read")
    configuring = args.origin_latitude is not None or args.origin_longitude is not None
    if configuring and (args.action != "mission.configure"
                        or args.origin_latitude is None or args.origin_longitude is None):
        parser.error("Mission configuration requires both origin coordinates and mission.configure.")
    engine = PolicyEngine(args.database)
    token = None
    try:
        token = engine.auth.login(args.username, getpass("Account password: "))
        if args.read_telemetry:
            records = engine.read_telemetry(token, args.uav_id)
            print(json.dumps({"uav_id": args.uav_id, "telemetry": records}, indent=2))
            return 0
        if configuring:
            decision = engine.configure_mission(
                token, args.uav_id, args.origin_latitude, args.origin_longitude)
        else:
            decision = engine.authorize(token, args.uav_id, args.action)
        print(f"{'ALLOW' if decision.allowed else 'DENY'} reason={decision.reason}")
        return 0 if decision.allowed else 1
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + "\n")
    finally:
        if token is not None:
            engine.auth.logout(token)


if __name__ == "__main__":
    raise SystemExit(main())
