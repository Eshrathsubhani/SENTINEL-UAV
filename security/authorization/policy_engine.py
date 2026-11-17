"""Authorize UAV resource access using current sessions, roles, and assignments."""

import argparse
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path

from security.authentication.auth_service import AuthService, AuthenticationError, _principal, _token_hash

ACTIONS = {
    "telemetry.read": "telemetry.read",
    "status.read": "status.read",
    "command.rtl": "command.request",
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
        resource = uav_id if isinstance(uav_id, str) and 1 <= len(uav_id) <= 128 else None
        action = action if isinstance(action, str) and 1 <= len(action) <= 128 else "invalid_action"
        with self.auth._transaction() as db:
            user = None
            try:
                user = _principal(db, _token_hash(token), int(self.auth.clock()))
            except AuthenticationError:
                reason = "invalid_session"
            else:
                reason = self._reason(db, user, resource, action)
            decision = Decision(
                reason == "allowed", reason, user["user_id"] if user else None, resource, action
            )
            db.execute("""
                INSERT INTO authorization_events (actor_id, target_id, action, decision, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (decision.user_id, resource, action,
                  "allow" if decision.allowed else "deny", reason))
        return decision

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
    args = parser.parse_args()
    engine = PolicyEngine(args.database)
    token = None
    try:
        token = engine.auth.login(args.username, getpass("Account password: "))
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
