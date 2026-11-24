"""Authorized storage of mission records. No flight commands are dispatched."""

import argparse
from getpass import getpass
import json
from pathlib import Path
import re
import sqlite3
from time import time_ns

from database.mission_repository import (
    MissionError,
    STATUSES,
    TRANSITIONS,
    clock_us,
    create_mission,
    get_mission,
    list_missions,
    transition_mission,
)
from database.security_event_repository import identifier
from database.telemetry_repository import (
    MAX_US,
    history_filter,
    query_history,
    timestamp_us,
)
from security.authentication.auth_service import (
    AuthService,
    AuthenticationError,
    _principal,
    _token_hash,
)
from security.authorization.policy_engine import PolicyEngine


def mission_identifier(value):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{32}", value) is None:
        raise ValueError("Mission ID must be 32 lowercase hexadecimal characters")
    return value


def mission_details(value):
    if value is None:
        value = {}
    if type(value) is not dict:
        raise ValueError("Mission details must be a JSON object")

    def check_keys(item, depth=0):
        if depth > 8:
            raise ValueError("Mission details are too deeply nested")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or not 1 <= len(key) <= 64:
                    raise ValueError("Invalid mission detail key")
                check_keys(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 100:
                raise ValueError("Mission detail list is too large")
            for child in item:
                check_keys(child, depth + 1)

    try:
        check_keys(value)
        encoded = json.dumps(
            value, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, RecursionError, OverflowError) as error:
        raise ValueError("Mission details must contain bounded JSON data") from error
    if len(encoded.encode("utf-8")) > 8192:
        raise ValueError("Mission details exceed 8192 bytes")
    return encoded


class MissionService:
    def __init__(self, database, *, clock=None):
        self.auth = AuthService(database)
        self.clock = clock or (lambda: time_ns() // 1000)

    def _request(self, token, uav_id, action, operation):
        identifier(uav_id, "UAV ID")
        result = None
        user = None
        now_us = clock_us(self.clock())
        with self.auth._transaction() as db:
            try:
                user = _principal(db, _token_hash(token), now_us // 1000000)
            except AuthenticationError:
                reason = "invalid_session"
            else:
                reason = PolicyEngine._reason(db, user, uav_id, action)
            if reason == "allowed":
                try:
                    result = operation(db, user["user_id"], now_us)
                except MissionError as error:
                    reason = str(error)
            db.execute(
                """INSERT INTO authorization_events(actor_id,target_id,action,decision,reason)
                          VALUES (?,?,?,?,?)""",
                (
                    user["user_id"] if user else None,
                    uav_id,
                    action,
                    "allow" if reason == "allowed" else "deny",
                    reason,
                ),
            )
        if reason != "allowed":
            raise PermissionError(reason)
        return result

    def create(self, token, uav_id, name, *, description="", details=None):
        if (
            not isinstance(name, str)
            or not 1 <= len(name.strip()) <= 128
            or any(ord(c) < 32 for c in name)
        ):
            raise ValueError("Mission name must contain 1 to 128 printable characters")
        if (
            not isinstance(description, str)
            or len(description) > 2048
            or any(ord(c) < 32 and c not in "\n\t" for c in description)
        ):
            raise ValueError("Invalid mission description")
        encoded = mission_details(details)
        return self._request(
            token,
            uav_id,
            "mission.record.create",
            lambda db, actor, now: create_mission(
                db, actor, uav_id, name.strip(), description, encoded, now
            ),
        )

    def transition(self, token, uav_id, mission_id, operation):
        mission_identifier(mission_id)
        if not isinstance(operation, str) or operation not in TRANSITIONS:
            raise ValueError("Unknown mission operation")
        return self._request(
            token,
            uav_id,
            "mission.record." + operation,
            lambda db, actor, now: transition_mission(
                db, actor, uav_id, mission_id, operation, now
            ),
        )

    def get(self, token, uav_id, mission_id):
        mission_identifier(mission_id)
        return self._request(
            token,
            uav_id,
            "mission.record.read",
            lambda db, actor, now: get_mission(db, uav_id, mission_id),
        )

    def history(
        self,
        token,
        uav_id,
        *,
        status=None,
        start=None,
        end=None,
        limit=100,
        before=None,
    ):
        if status is not None and (
            not isinstance(status, str) or status not in STATUSES
        ):
            raise ValueError("Unknown mission status")
        start = timestamp_us(start) if start is not None else None
        end = timestamp_us(end) if end is not None else None
        if (
            (start is not None and not 0 <= start <= MAX_US)
            or (end is not None and not 0 <= end <= MAX_US)
            or (start is not None and end is not None and start >= end)
        ):
            raise ValueError("Invalid mission time range")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Page size must be 1 to 1000")
        if before is not None:
            if (
                type(before) is not list
                or len(before) != 2
                or type(before[0]) is not int
                or not 0 <= before[0] <= MAX_US
            ):
                raise ValueError("Invalid mission cursor")
            mission_identifier(before[1])
        return self._request(
            token,
            uav_id,
            "mission.record.read",
            lambda db, actor, now: list_missions(
                db,
                uav_id,
                status=status,
                start=start,
                end=end,
                limit=limit,
                before=before,
            ),
        )

    def telemetry(
        self, token, uav_id, mission_id, start, end, *, limit=100, cursor=None
    ):
        mission_identifier(mission_id)
        filters = history_filter(start, end, limit, cursor)

        def read(db, actor, now):
            get_mission(db, uav_id, mission_id)
            return {
                "mission_id": mission_id,
                **query_history(db, uav_id, filters, mission_id=mission_id),
            }

        return self._request(token, uav_id, "mission.record.telemetry", read)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--uav-id", required=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    create = sub.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--description", default="")
    create.add_argument(
        "--details",
        default="{}",
        help="JSON object containing non-secret mission metadata",
    )
    for operation in ("get", "start", "complete", "abort", "cancel"):
        child = sub.add_parser(operation)
        child.add_argument("--mission-id", required=True)
    history = sub.add_parser("list")
    history.add_argument("--status", choices=sorted(STATUSES))
    history.add_argument("--from-time")
    history.add_argument("--to-time")
    history.add_argument("--limit", type=int, default=100)
    history.add_argument(
        "--before", help="JSON [created_at_us,mission_id] from next_before"
    )
    telemetry = sub.add_parser("telemetry")
    telemetry.add_argument("--mission-id", required=True)
    telemetry.add_argument("--from-time", required=True)
    telemetry.add_argument("--to-time", required=True)
    telemetry.add_argument("--limit", type=int, default=100)
    telemetry.add_argument("--cursor")
    args = parser.parse_args()
    token = None
    service = MissionService(args.database)
    try:
        token = service.auth.login(args.username, getpass("Account password: "))
        if args.operation == "create":
            result = service.create(
                token,
                args.uav_id,
                args.name,
                description=args.description,
                details=json.loads(args.details),
            )
        elif args.operation == "get":
            result = service.get(token, args.uav_id, args.mission_id)
        elif args.operation == "list":
            result = service.history(
                token,
                args.uav_id,
                status=args.status,
                start=args.from_time,
                end=args.to_time,
                limit=args.limit,
                before=json.loads(args.before) if args.before else None,
            )
        elif args.operation == "telemetry":
            result = service.telemetry(
                token,
                args.uav_id,
                args.mission_id,
                args.from_time,
                args.to_time,
                limit=args.limit,
                cursor=args.cursor,
            )
        else:
            result = service.transition(
                token, args.uav_id, args.mission_id, args.operation
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
