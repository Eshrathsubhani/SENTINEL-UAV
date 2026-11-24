"""Administrator-only SQLite backup and restore to a new file."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
from getpass import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import time

from database.security_event_repository import append_event
from security.authentication.auth_service import AuthService


def verify(connection):
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("Database integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ValueError("Database foreign-key check failed")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version != 10:
        raise ValueError(f"Expected schema 10; found {version}")


def copy_database(source, destination, *, revoke_sessions=False):
    source = Path(source).expanduser().resolve(strict=True)
    destination = Path(destination).expanduser().absolute()
    if not source.is_file():
        raise ValueError("Source must be a database file")

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
    )
    os.close(descriptor)

    try:
        with closing(sqlite3.connect(
            source.as_uri() + "?mode=ro", uri=True, timeout=10
        )) as reader, closing(sqlite3.connect(destination)) as writer:
            reader.backup(writer)
            writer.execute("PRAGMA foreign_keys=ON")
            verify(writer)

            if revoke_sessions:
                with writer:
                    writer.execute(
                        """UPDATE sessions
                           SET revoked_at_epoch=?
                           WHERE revoked_at_epoch IS NULL""",
                        (int(time.time()),),
                    )
                verify(writer)

        digest = sha256(destination.read_bytes()).hexdigest()
        return {
            "result": "PASS",
            "destination": str(destination),
            "schema_version": 10,
            "sha256": digest,
            "sessions_revoked": revoke_sessions,
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("operation", choices=("backup", "restore"))
    args = parser.parse_args()

    os.umask(0o077)
    if not args.database.is_file():
        parser.error("The administrator authentication database must exist")
    if args.operation == "restore" and args.source is None:
        parser.error("Restore requires --source")

    auth = AuthService(args.database)
    token = None
    try:
        token = auth.login(args.username, getpass("Administrator password: "))
        with auth.administrator_transaction(
            token, "database." + args.operation
        ) as (database, actor):
            report = copy_database(
                args.database if args.operation == "backup" else args.source,
                args.destination,
                revoke_sessions=args.operation == "restore",
            )
            append_event(
                database,
                "storage_maintenance",
                "storage",
                "database." + args.operation + ".completed",
                actor_id=actor["user_id"],
                outcome="success",
                details={"reason": "verified_new_file"},
            )
        print(json.dumps(report, indent=2))
        return 0
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, str(error) + "\n")
    finally:
        if token is not None:
            auth.logout(token)


if __name__ == "__main__":
    raise SystemExit(main())