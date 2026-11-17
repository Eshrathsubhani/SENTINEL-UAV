"""Initialize the persistent Phase 4 identity schema."""

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA_VERSION = 2
PERMISSIONS = {
    "Administrator": (
        "telemetry.read", "status.read", "command.request", "users.manage",
        "uavs.manage", "assignments.manage", "audit.read", "policies.manage",
    ),
    "Operator": ("telemetry.read", "status.read", "command.request", "audit.read_own"),
    "Viewer": ("telemetry.read", "status.read"),
}
SCHEMA = (
    """CREATE TABLE roles (
        name TEXT PRIMARY KEY CHECK(name IN ('Administrator', 'Operator', 'Viewer'))
    )""",
    """CREATE TABLE permissions (name TEXT PRIMARY KEY)""",
    """CREATE TABLE role_permissions (
        role_name TEXT REFERENCES roles(name),
        permission_name TEXT REFERENCES permissions(name),
        PRIMARY KEY(role_name, permission_name)
    )""",
    """CREATE TABLE users (
        user_id TEXT PRIMARY KEY NOT NULL,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(length(trim(username)) > 0),
        password_hash TEXT NOT NULL CHECK(password_hash LIKE '$argon2id$%'),
        role_name TEXT NOT NULL REFERENCES roles(name),
        status TEXT NOT NULL DEFAULT 'active'
            CHECK(status IN ('active', 'suspended', 'revoked')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE uavs (
        uav_id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL CHECK(length(trim(name)) > 0),
        description TEXT NOT NULL DEFAULT '',
        system_id INTEGER NOT NULL UNIQUE CHECK(system_id BETWEEN 1 AND 255),
        certificate_identity TEXT NOT NULL UNIQUE,
        signing_key_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK(status IN ('pending', 'active', 'suspended', 'revoked')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE uav_assignments (
        user_id TEXT NOT NULL REFERENCES users(user_id),
        uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
        assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id, uav_id)
    )""",
    """CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY NOT NULL CHECK(length(token_hash) = 64),
        user_id TEXT NOT NULL REFERENCES users(user_id),
        created_at_epoch INTEGER NOT NULL,
        expires_at_epoch INTEGER NOT NULL CHECK(expires_at_epoch > created_at_epoch),
        revoked_at_epoch INTEGER
    )""",
    """CREATE INDEX sessions_user ON sessions(user_id)""",
    """CREATE INDEX assignments_uav ON uav_assignments(uav_id)""",
    """CREATE TABLE policies (
        name TEXT PRIMARY KEY NOT NULL,
        configuration_json TEXT NOT NULL,
        version INTEGER NOT NULL CHECK(version > 0),
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE authorization_events (
        event_id INTEGER PRIMARY KEY,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        actor_id TEXT,
        target_id TEXT,
        action TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
        reason TEXT NOT NULL
    )""",
    """CREATE INDEX authorization_actor ON authorization_events(actor_id, event_id)""",
    """CREATE TABLE identity_events (
        event_id INTEGER PRIMARY KEY,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        actor_id TEXT,
        target_id TEXT,
        event TEXT NOT NULL,
        reason TEXT NOT NULL
    )""",
)


def connect_database(path):
    """Open a connection with foreign keys enforced for every caller."""
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(path):
    """Create version one atomically, preserving existing data on repeated calls."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect_database(path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version == 1:
            connection.execute("""
                CREATE TABLE login_attempts (
                    username TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL CHECK(failures >= 0),
                    window_start_epoch INTEGER NOT NULL,
                    blocked_until_epoch INTEGER NOT NULL DEFAULT 0)
            """)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            return
        if version != 0:
            raise ValueError(f"Unsupported identity schema version {version}")
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if tables:
            raise ValueError("Use an empty database or an initialized identity database")
        for statement in SCHEMA:
            connection.execute(statement)
        for role, permissions in PERMISSIONS.items():
            connection.execute("INSERT INTO roles VALUES (?)", (role,))
            for permission in permissions:
                connection.execute("INSERT OR IGNORE INTO permissions VALUES (?)", (permission,))
                connection.execute("INSERT INTO role_permissions VALUES (?, ?)", (role, permission))
        connection.execute("""
            CREATE TABLE login_attempts (
                username TEXT PRIMARY KEY,
                failures INTEGER NOT NULL CHECK(failures >= 0),
                window_start_epoch INTEGER NOT NULL,
                blocked_until_epoch INTEGER NOT NULL DEFAULT 0)
        """)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    initialize_database(args.database)
    print(f"Identity database ready at {args.database} (schema {SCHEMA_VERSION})")


if __name__ == "__main__":
    main()
