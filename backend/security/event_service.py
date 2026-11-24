"""Read centralized security/audit events with current backend authorization."""

import argparse
from getpass import getpass
import json
from pathlib import Path
import sqlite3

from database.security_event_repository import (
    CATEGORIES,
    SEVERITIES,
    identifier,
    query_events,
)
from database.telemetry_repository import timestamp_us
from security.authentication.auth_service import (
    AuthService,
    AuthenticationError,
    _principal,
    _token_hash,
)


class SecurityEventService:
    def __init__(self, database):
        self.auth = AuthService(database)

    def query(
        self,
        token,
        *,
        category=None,
        severity=None,
        uav_id=None,
        start=None,
        end=None,
        limit=100,
        before=None,
    ):
        if category is not None and (
            not isinstance(category, str) or category not in CATEGORIES
        ):
            raise ValueError("Unknown event category")
        if severity is not None and (
            not isinstance(severity, str) or severity not in SEVERITIES
        ):
            raise ValueError("Unknown severity")
        identifier(uav_id, "UAV ID", optional=True)
        start = timestamp_us(start) if start is not None else None
        end = timestamp_us(end) if end is not None else None
        if start is not None and end is not None and start >= end:
            raise ValueError("Invalid event time range")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Page size must be 1 to 1000")
        if before is not None and (
            type(before) is not list
            or len(before) != 2
            or type(before[0]) is not int
            or not 0 <= before[0] <= 253402300799999999
            or type(before[1]) is not int
            or not 1 <= before[1] < 2**63
        ):
            raise ValueError("Invalid event cursor")
        result = None
        actor = None
        reason = "invalid_session"
        with self.auth._transaction() as db:
            try:
                actor = _principal(db, _token_hash(token), int(self.auth.clock()))
            except AuthenticationError:
                pass
            if actor:
                permissions = {
                    r[0]
                    for r in db.execute(
                        "SELECT permission_name FROM role_permissions WHERE role_name=?",
                        (actor["role_name"],),
                    )
                }
                if "audit.read" in permissions:
                    scope, reason = None, "allowed"
                elif "audit.read_own" in permissions:
                    scope, reason = actor["user_id"], "allowed"
                else:
                    scope, reason = None, "role_denied"
            db.execute(
                "INSERT INTO authorization_events (actor_id,action,decision,reason) VALUES (?,?,?,?)",
                (
                    actor["user_id"] if actor else None,
                    "security_events.read",
                    "allow" if reason == "allowed" else "deny",
                    reason,
                ),
            )
            if reason == "allowed":
                result = query_events(
                    db,
                    actor_scope=scope,
                    category=category,
                    severity=severity,
                    uav_id=uav_id,
                    start=start,
                    end=end,
                    limit=limit,
                    before=before,
                )
        if result is None:
            raise PermissionError(reason)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--category", choices=sorted(CATEGORIES))
    parser.add_argument("--severity", choices=sorted(SEVERITIES))
    parser.add_argument("--uav-id")
    parser.add_argument("--from-time")
    parser.add_argument("--to-time")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--before", help="JSON array [occurred_at_us,event_id] from next_before"
    )
    args = parser.parse_args()
    service = SecurityEventService(args.database)
    token = None
    try:
        token = service.auth.login(args.username, getpass("Account password: "))
        result = service.query(
            token,
            category=args.category,
            severity=args.severity,
            uav_id=args.uav_id,
            start=args.from_time,
            end=args.to_time,
            limit=args.limit,
            before=json.loads(args.before) if args.before else None,
        )
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, str(error) + "\n")
    finally:
        if token is not None:
            service.auth.logout(token)


if __name__ == "__main__":
    raise SystemExit(main())
