"""Frozen version-1 identity schema and initial role permissions."""

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
