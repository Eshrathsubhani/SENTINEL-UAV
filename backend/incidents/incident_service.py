"""Administrator incident management over the existing identity/security database."""

import argparse
from getpass import getpass
import json
from pathlib import Path
import re
import sqlite3
from time import time_ns

from database import incident_repository as repository
from database.security_event_repository import SEVERITIES, identifier
from database.telemetry_repository import MAX_US, timestamp_us
from security.authentication.auth_service import (
    AuthService,
    AuthenticationError,
    _principal,
    _token_hash,
)


def incident_id(value):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{32}", value) is None:
        raise ValueError("Invalid incident ID")
    return value


def bounded_text(value, label, maximum, *, required=True):
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or (required and not value.strip())
        or any(ord(c) < 32 and c not in "\n\t" for c in value)
    ):
        raise ValueError("Invalid " + label)
    return value.strip()


def classification(attack_type, severity):
    if not isinstance(attack_type, str) or attack_type not in repository.ATTACK_TYPES:
        raise ValueError("Unknown attack type")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ValueError("Unknown severity")


def event_ids(values):
    if values is None:
        return []
    if (
        type(values) is not list
        or len(values) > 100
        or any(type(v) is not int or not 1 <= v < 2**63 for v in values)
    ):
        raise ValueError("Supply at most 100 positive security event IDs")
    return list(dict.fromkeys(values))


def page_size(limit):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Page size must be 1 to 1000")


class IncidentService:
    def __init__(self, database, *, clock=None):
        self.auth = AuthService(database)
        self.clock = clock or (lambda: time_ns() // 1000)

    def _request(self, token, action, target, operation):
        now = self.clock()
        if type(now) is not int or not 0 <= now <= MAX_US:
            raise ValueError("Invalid incident clock")
        actor = None
        result = None
        reason = "invalid_session"
        with self.auth._transaction() as db:
            try:
                actor = _principal(db, _token_hash(token), now // 1000000)
            except AuthenticationError:
                pass
            if actor:
                allowed = db.execute(
                    "SELECT 1 FROM role_permissions WHERE role_name=? AND permission_name='audit.read'",
                    (actor["role_name"],),
                ).fetchone()
                reason = (
                    "allowed"
                    if actor["role_name"] == "Administrator" and allowed
                    else "role_denied"
                )
            if reason == "allowed":
                try:
                    result = operation(db, actor["user_id"], now)
                except repository.IncidentError as error:
                    reason = str(error)
            db.execute(
                "INSERT INTO authorization_events(actor_id,target_id,action,decision,reason) VALUES (?,?,?,?,?)",
                (
                    actor["user_id"] if actor else None,
                    target,
                    "incident." + action,
                    "allow" if reason == "allowed" else "deny",
                    reason,
                ),
            )
        if reason != "allowed":
            raise PermissionError(reason)
        return result

    def create(
        self,
        token,
        title,
        *,
        description="",
        attack_type="other",
        severity="medium",
        uav_id=None,
        security_event_ids=None,
    ):
        title = bounded_text(title, "title", 128)
        description = bounded_text(description, "description", 4096, required=False)
        classification(attack_type, severity)
        identifier(uav_id, "UAV ID", optional=True)
        links = event_ids(security_event_ids)
        return self._request(
            token,
            "create",
            uav_id,
            lambda db, actor, now: repository.create_incident(
                db, actor, now, title, description, attack_type, severity, uav_id, links
            ),
        )

    def get(self, token, identity):
        incident_id(identity)
        return self._request(
            token,
            "read",
            identity,
            lambda db, actor, now: repository.get_incident(db, identity),
        )

    def link_events(self, token, identity, security_event_ids):
        incident_id(identity)
        links = event_ids(security_event_ids)
        if not links:
            raise ValueError("At least one security event ID is required")
        return self._request(
            token,
            "link",
            identity,
            lambda db, actor, now: repository.add_links(
                db, identity, actor, now, links
            ),
        )

    def add_note(self, token, identity, body):
        incident_id(identity)
        body = bounded_text(body, "investigation note", 4096)
        return self._request(
            token,
            "note",
            identity,
            lambda db, actor, now: repository.add_note(db, identity, actor, now, body),
        )

    def investigate(self, token, identity):
        incident_id(identity)
        return self._request(
            token,
            "investigate",
            identity,
            lambda db, actor, now: repository.change_status(
                db, identity, actor, now, "investigating", ""
            ),
        )

    def resolve(self, token, identity, resolution):
        incident_id(identity)
        resolution = bounded_text(resolution, "resolution", 4096)
        return self._request(
            token,
            "resolve",
            identity,
            lambda db, actor, now: repository.change_status(
                db, identity, actor, now, "resolved", resolution
            ),
        )

    def classify(self, token, identity, attack_type, severity):
        incident_id(identity)
        classification(attack_type, severity)
        return self._request(
            token,
            "classify",
            identity,
            lambda db, actor, now: repository.classify(
                db, identity, actor, now, attack_type, severity
            ),
        )

    def list(
        self,
        token,
        *,
        status=None,
        severity=None,
        attack_type=None,
        uav_id=None,
        start=None,
        end=None,
        limit=100,
        before=None,
    ):
        for value, choices, label in (
            (status, repository.STATUSES, "status"),
            (severity, SEVERITIES, "severity"),
            (attack_type, repository.ATTACK_TYPES, "attack type"),
        ):
            if value is not None and (
                not isinstance(value, str) or value not in choices
            ):
                raise ValueError("Unknown " + label)
        identifier(uav_id, "UAV ID", optional=True)
        page_size(limit)
        start = timestamp_us(start) if start is not None else None
        end = timestamp_us(end) if end is not None else None
        if (
            (start is not None and not 0 <= start <= MAX_US)
            or (end is not None and not 0 <= end <= MAX_US)
            or (start is not None and end is not None and start >= end)
        ):
            raise ValueError("Invalid incident time range")
        if before is not None:
            if (
                type(before) is not list
                or len(before) != 2
                or type(before[0]) is not int
                or not 0 <= before[0] <= MAX_US
            ):
                raise ValueError("Invalid incident cursor")
            incident_id(before[1])
        return self._request(
            token,
            "list",
            None,
            lambda db, actor, now: repository.list_incidents(
                db,
                status=status,
                severity=severity,
                attack_type=attack_type,
                uav_id=uav_id,
                start=start,
                end=end,
                limit=limit,
                before=before,
            ),
        )

    def page(self, token, identity, component, *, limit=100, before=None):
        incident_id(identity)
        page_size(limit)
        if not isinstance(component, str) or component not in (
            "notes",
            "events",
            "history",
        ):
            raise ValueError("Unknown incident component")
        if before is not None and (type(before) is not int or not 1 <= before < 2**63):
            raise ValueError("Invalid component cursor")
        return self._request(
            token,
            component,
            identity,
            lambda db, actor, now: repository.components(
                db, identity, component, limit, before
            ),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    commands = parser.add_subparsers(dest="operation", required=True)
    create = commands.add_parser("create")
    create.add_argument("--title", required=True)
    create.add_argument("--description", default="")
    create.add_argument(
        "--attack-type", choices=sorted(repository.ATTACK_TYPES), default="other"
    )
    create.add_argument("--severity", choices=sorted(SEVERITIES), default="medium")
    create.add_argument("--uav-id")
    create.add_argument("--event-id", type=int, action="append", default=[])
    for operation in (
        "get",
        "link",
        "note",
        "investigate",
        "resolve",
        "classify",
        "notes",
        "events",
        "history",
    ):
        child = commands.add_parser(operation)
        child.add_argument("--incident-id", required=True)
        if operation == "link":
            child.add_argument("--event-id", type=int, action="append", required=True)
        if operation == "note":
            child.add_argument("--body", required=True)
        if operation == "resolve":
            child.add_argument("--resolution", required=True)
        if operation == "classify":
            child.add_argument(
                "--attack-type", choices=sorted(repository.ATTACK_TYPES), required=True
            )
            child.add_argument("--severity", choices=sorted(SEVERITIES), required=True)
        if operation in ("notes", "events", "history"):
            child.add_argument("--limit", type=int, default=100)
            child.add_argument("--before", type=int)
    listing = commands.add_parser("list")
    listing.add_argument("--status", choices=sorted(repository.STATUSES))
    listing.add_argument("--severity", choices=sorted(SEVERITIES))
    listing.add_argument("--attack-type", choices=sorted(repository.ATTACK_TYPES))
    listing.add_argument("--uav-id")
    listing.add_argument("--from-time")
    listing.add_argument("--to-time")
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--before", help="JSON [created_at_us,incident_id]")
    args = parser.parse_args()
    service = IncidentService(args.database)
    token = None
    try:
        token = service.auth.login(args.username, getpass("Account password: "))
        op = args.operation
        if op == "create":
            result = service.create(
                token,
                args.title,
                description=args.description,
                attack_type=args.attack_type,
                severity=args.severity,
                uav_id=args.uav_id,
                security_event_ids=args.event_id,
            )
        elif op == "list":
            result = service.list(
                token,
                status=args.status,
                severity=args.severity,
                attack_type=args.attack_type,
                uav_id=args.uav_id,
                start=args.from_time,
                end=args.to_time,
                limit=args.limit,
                before=json.loads(args.before) if args.before else None,
            )
        elif op in ("notes", "events", "history"):
            result = service.page(
                token, args.incident_id, op, limit=args.limit, before=args.before
            )
        elif op == "get":
            result = service.get(token, args.incident_id)
        elif op == "link":
            result = service.link_events(token, args.incident_id, args.event_id)
        elif op == "note":
            result = service.add_note(token, args.incident_id, args.body)
        elif op == "investigate":
            result = service.investigate(token, args.incident_id)
        elif op == "resolve":
            result = service.resolve(token, args.incident_id, args.resolution)
        else:
            result = service.classify(
                token, args.incident_id, args.attack_type, args.severity
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
