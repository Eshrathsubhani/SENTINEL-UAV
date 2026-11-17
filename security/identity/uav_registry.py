"""Register UAV identity mappings and manage explicit user assignments."""

import argparse
from contextlib import contextmanager
from getpass import getpass
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

from security.authentication.auth_service import AuthService, AuthenticationError, _event, _principal, _token_hash


def _signing_id(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise ValueError("Signing key ID must be a SHA-256 hexadecimal fingerprint")
    return value.lower()


class UAVRegistry:
    """Perform administrator checks and changes within the same write transaction."""

    def __init__(self, database):
        self.auth = AuthService(database)

    @contextmanager
    def _administrator(self, token):
        token_hash = _token_hash(token)
        with self.auth._transaction() as db:
            actor = _principal(db, token_hash, int(self.auth.clock()))
            if actor["role_name"] != "Administrator":
                raise AuthenticationError("Administrator permission required")
            yield db, actor["user_id"]

    def register(self, token, name, system_id, certificate_identity, signing_key_id, description=""):
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 128:
            raise ValueError("UAV name must contain 1 to 128 characters")
        if type(system_id) is not int or not 1 <= system_id <= 255:
            raise ValueError("MAVLink system ID must be between 1 and 255")
        if not isinstance(certificate_identity, str) or re.fullmatch(
            r"urn:sentinel:uav:[A-Za-z0-9_.-]{1,64}", certificate_identity
        ) is None:
            raise ValueError("Expected a certificate URI such as urn:sentinel:uav:1")
        signing_key_id = _signing_id(signing_key_id)
        if not isinstance(description, str) or len(description) > 2048:
            raise ValueError("Description must contain at most 2048 characters")
        uav_id = uuid4().hex
        with self._administrator(token) as (db, actor):
            db.execute("""
                INSERT INTO uavs
                (uav_id, name, description, system_id, certificate_identity, signing_key_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uav_id, name.strip(), description, system_id, certificate_identity, signing_key_id))
            _event(db, actor, uav_id, "uav_registered", "pending")
        return uav_id

    def set_status(self, token, uav_id, status):
        if status not in ("active", "suspended", "revoked"):
            raise ValueError("Unknown UAV status")
        with self._administrator(token) as (db, actor):
            row = db.execute("SELECT status FROM uavs WHERE uav_id = ?", (uav_id,)).fetchone()
            if row is None:
                raise ValueError("Unknown UAV")
            if row["status"] == "revoked" and status != "revoked":
                raise ValueError("A revoked UAV cannot be reactivated")
            if row["status"] == status:
                return
            db.execute("UPDATE uavs SET status = ? WHERE uav_id = ?", (status, uav_id))
            _event(db, actor, uav_id, "uav_status_changed", status)

    def assign(self, token, user_id, uav_id):
        with self._administrator(token) as (db, actor):
            user = db.execute("SELECT status FROM users WHERE user_id = ?", (user_id,)).fetchone()
            uav = db.execute("SELECT status FROM uavs WHERE uav_id = ?", (uav_id,)).fetchone()
            if user is None or uav is None:
                raise ValueError("Unknown user or UAV")
            if user["status"] != "active" or uav["status"] != "active":
                raise ValueError("Assignments require an active user and active UAV")
            result = db.execute(
                "INSERT OR IGNORE INTO uav_assignments (user_id, uav_id) VALUES (?, ?)",
                (user_id, uav_id),
            )
            if result.rowcount:
                _event(db, actor, uav_id, "uav_assigned", user_id)

    def unassign(self, token, user_id, uav_id):
        with self._administrator(token) as (db, actor):
            result = db.execute(
                "DELETE FROM uav_assignments WHERE user_id = ? AND uav_id = ?", (user_id, uav_id)
            )
            if result.rowcount:
                _event(db, actor, uav_id, "uav_unassigned", user_id)

    def list_uavs(self, token):
        with self._administrator(token) as (db, _):
            return [dict(row) for row in db.execute("SELECT * FROM uavs ORDER BY created_at, uav_id")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    commands = parser.add_subparsers(dest="command", required=True)
    register = commands.add_parser("register")
    register.add_argument("--name", required=True)
    register.add_argument("--system-id", type=int, required=True)
    register.add_argument("--certificate-identity", required=True)
    register.add_argument("--signing-key-id", required=True)
    commands.add_parser("list")
    status = commands.add_parser("set-status")
    status.add_argument("--uav-id", required=True)
    status.add_argument("--status", choices=("active", "suspended", "revoked"), required=True)
    for command in ("assign", "unassign"):
        action = commands.add_parser(command)
        action.add_argument("--user-id", required=True)
        action.add_argument("--uav-id", required=True)
    args = parser.parse_args()
    registry = UAVRegistry(args.database)
    token = None
    try:
        token = registry.auth.login(args.username, getpass("Administrator password: "))
        if args.command == "register":
            uav_id = registry.register(token, args.name, args.system_id,
                                       args.certificate_identity, args.signing_key_id)
            print(f"UAV registered with ID {uav_id} and status pending")
        elif args.command == "list":
            for uav in registry.list_uavs(token):
                print(f"{uav['uav_id']} | {uav['name']} | system={uav['system_id']} | {uav['status']}")
        elif args.command == "set-status":
            registry.set_status(token, args.uav_id, args.status)
            print("UAV status updated")
        elif args.command == "assign":
            registry.assign(token, args.user_id, args.uav_id)
            print("UAV assignment recorded")
        else:
            registry.unassign(token, args.user_id, args.uav_id)
            print("UAV assignment removed")
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, str(error) + "\n")
    finally:
        if token is not None:
            registry.auth.logout(token)


if __name__ == "__main__":
    main()
