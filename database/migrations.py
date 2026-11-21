"""Ordered schema migrations for identity and accepted telemetry history.

Run only within an explicit transaction. Never use executescript here, because
it can commit the caller's transaction before all migrations finish.
"""

from database.schema_v1 import PERMISSIONS, SCHEMA


def version_1(connection):
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


def version_2(connection):
    connection.execute("""
        CREATE TABLE login_attempts (
            username TEXT PRIMARY KEY,
            failures INTEGER NOT NULL CHECK(failures >= 0),
            window_start_epoch INTEGER NOT NULL,
            blocked_until_epoch INTEGER NOT NULL DEFAULT 0)
    """)


def version_3(connection):
    connection.execute("""
        CREATE TABLE telemetry_snapshots (
            uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
            message_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            received_at_utc TEXT NOT NULL,
            PRIMARY KEY(uav_id, message_type))
    """)


def version_4(connection):
    connection.execute("""
        CREATE TABLE command_requests (
            request_id TEXT PRIMARY KEY NOT NULL,
            token_hash TEXT NOT NULL REFERENCES sessions(token_hash),
            uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
            action TEXT NOT NULL CHECK(action = 'command.status'),
            created_at_epoch INTEGER NOT NULL,
            expires_at_epoch INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN
                ('queued', 'dispatching', 'sent', 'denied', 'failed')),
            reason TEXT NOT NULL)
    """)
    connection.execute("CREATE INDEX pending_commands ON command_requests(status, uav_id)")


def version_5(connection):
    connection.execute("""
        CREATE TABLE telemetry_records (
            record_id TEXT PRIMARY KEY NOT NULL CHECK(length(record_id) BETWEEN 1 AND 128),
            uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
            captured_at_us INTEGER NOT NULL,
            received_at_us INTEGER NOT NULL,
            message_type TEXT NOT NULL CHECK(message_type IN ('HEARTBEAT','GLOBAL_POSITION_INT')),
            system_id INTEGER NOT NULL CHECK(system_id BETWEEN 1 AND 255),
            component_id INTEGER NOT NULL CHECK(component_id BETWEEN 1 AND 255),
            source TEXT NOT NULL CHECK(source = 'authenticated_uav_gateway'),
            validation_status TEXT NOT NULL CHECK(validation_status = 'gateway_attested'),
            payload_json TEXT NOT NULL)
    """)
    connection.execute("CREATE INDEX telemetry_uav_time ON telemetry_records(uav_id,captured_at_us,record_id)")


def version_6(connection):
    connection.execute("""
        CREATE TABLE telemetry_records_v6 (
            record_id TEXT PRIMARY KEY NOT NULL CHECK(length(record_id) BETWEEN 1 AND 128),
            uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
            captured_at_us INTEGER NOT NULL,
            received_at_us INTEGER NOT NULL,
            message_type TEXT NOT NULL CHECK(message_type IN ('HEARTBEAT','GLOBAL_POSITION_INT','SYS_STATUS','BATTERY_STATUS')),
            system_id INTEGER NOT NULL CHECK(system_id BETWEEN 1 AND 255),
            component_id INTEGER NOT NULL CHECK(component_id BETWEEN 1 AND 255),
            source TEXT NOT NULL CHECK(source = 'authenticated_uav_gateway'),
            validation_status TEXT NOT NULL CHECK(validation_status = 'gateway_attested'),
            payload_json TEXT NOT NULL)
    """)
    connection.execute("INSERT INTO telemetry_records_v6 SELECT * FROM telemetry_records")
    connection.execute("DROP TABLE telemetry_records")
    connection.execute("ALTER TABLE telemetry_records_v6 RENAME TO telemetry_records")
    connection.execute("CREATE INDEX telemetry_uav_time ON telemetry_records(uav_id,captured_at_us,record_id)")


def version_7(connection):
    connection.execute("""
        CREATE TABLE communication_state (
            uav_id TEXT PRIMARY KEY NOT NULL REFERENCES uavs(uav_id),
            state TEXT NOT NULL CHECK(state IN ('connected','lost')),
            last_captured_at_us INTEGER NOT NULL,
            last_received_at_us INTEGER NOT NULL,
            timeout_us INTEGER NOT NULL CHECK(timeout_us > 0),
            signing_key_id TEXT NOT NULL,
            certificate_identity TEXT NOT NULL)
    """)
    connection.execute("""
        CREATE TABLE communication_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
            occurred_at_us INTEGER NOT NULL,
            event TEXT NOT NULL CHECK(event IN
                ('heartbeat_received','heartbeat_lost','heartbeat_recovered')),
            source TEXT NOT NULL CHECK(source='gcs_accepted_heartbeat'),
            reason TEXT NOT NULL,
            record_id TEXT REFERENCES telemetry_records(record_id) ON DELETE SET NULL)
    """)
    connection.execute("CREATE INDEX communication_uav_time ON communication_events(uav_id,occurred_at_us,event_id)")


MIGRATIONS = (version_1, version_2, version_3, version_4, version_5, version_6, version_7)
SCHEMA_VERSION = len(MIGRATIONS)


def apply_migrations(connection):
    """Apply each pending step; caller owns commit/rollback and writer lock."""
    if not connection.in_transaction:
        raise RuntimeError("Schema migrations require an explicit transaction")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if not 0 <= version <= SCHEMA_VERSION:
        raise ValueError(f"Unsupported identity schema version {version}")
    for index in range(version, SCHEMA_VERSION):
        MIGRATIONS[index](connection)
        # The version is derived from the internal ordered migration list.
        connection.execute(f"PRAGMA user_version = {index + 1}")
