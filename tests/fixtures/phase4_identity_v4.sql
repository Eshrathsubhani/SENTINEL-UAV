-- Synthetic fixture generated using the original Phase 4 version-4 initializer.
BEGIN TRANSACTION;
CREATE TABLE authorization_events (
        event_id INTEGER PRIMARY KEY,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        actor_id TEXT,
        target_id TEXT,
        action TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
        reason TEXT NOT NULL
    );
INSERT INTO "authorization_events" VALUES(1,'2026-01-01 00:00:00','fixture-user','fixture-uav','telemetry.read','allow','fixture');
CREATE TABLE command_requests (
                request_id TEXT PRIMARY KEY NOT NULL,
                token_hash TEXT NOT NULL REFERENCES sessions(token_hash),
                uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
                action TEXT NOT NULL CHECK(action = 'command.status'),
                created_at_epoch INTEGER NOT NULL,
                expires_at_epoch INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN
                    ('queued', 'dispatching', 'sent', 'denied', 'failed')),
                reason TEXT NOT NULL);
INSERT INTO "command_requests" VALUES('fixture-request','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','fixture-uav','command.status',10,20,'sent','transport_write_completed');
CREATE TABLE identity_events (
        event_id INTEGER PRIMARY KEY,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        actor_id TEXT,
        target_id TEXT,
        event TEXT NOT NULL,
        reason TEXT NOT NULL
    );
INSERT INTO "identity_events" VALUES(1,'2026-01-01 00:00:00','fixture-user','fixture-uav','registered','fixture');
CREATE TABLE login_attempts (
                    username TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL CHECK(failures >= 0),
                    window_start_epoch INTEGER NOT NULL,
                    blocked_until_epoch INTEGER NOT NULL DEFAULT 0);
INSERT INTO "login_attempts" VALUES('fixture-admin',1,10,0);
CREATE TABLE permissions (name TEXT PRIMARY KEY);
INSERT INTO "permissions" VALUES('telemetry.read');
INSERT INTO "permissions" VALUES('status.read');
INSERT INTO "permissions" VALUES('command.request');
INSERT INTO "permissions" VALUES('users.manage');
INSERT INTO "permissions" VALUES('uavs.manage');
INSERT INTO "permissions" VALUES('assignments.manage');
INSERT INTO "permissions" VALUES('audit.read');
INSERT INTO "permissions" VALUES('policies.manage');
INSERT INTO "permissions" VALUES('audit.read_own');
CREATE TABLE policies (
        name TEXT PRIMARY KEY NOT NULL,
        configuration_json TEXT NOT NULL,
        version INTEGER NOT NULL CHECK(version > 0),
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
INSERT INTO "policies" VALUES('fixture-policy','{}',1,'2026-01-01 00:00:00');
CREATE TABLE role_permissions (
        role_name TEXT REFERENCES roles(name),
        permission_name TEXT REFERENCES permissions(name),
        PRIMARY KEY(role_name, permission_name)
    );
INSERT INTO "role_permissions" VALUES('Administrator','telemetry.read');
INSERT INTO "role_permissions" VALUES('Administrator','status.read');
INSERT INTO "role_permissions" VALUES('Administrator','command.request');
INSERT INTO "role_permissions" VALUES('Administrator','users.manage');
INSERT INTO "role_permissions" VALUES('Administrator','uavs.manage');
INSERT INTO "role_permissions" VALUES('Administrator','assignments.manage');
INSERT INTO "role_permissions" VALUES('Administrator','audit.read');
INSERT INTO "role_permissions" VALUES('Administrator','policies.manage');
INSERT INTO "role_permissions" VALUES('Operator','telemetry.read');
INSERT INTO "role_permissions" VALUES('Operator','status.read');
INSERT INTO "role_permissions" VALUES('Operator','command.request');
INSERT INTO "role_permissions" VALUES('Operator','audit.read_own');
INSERT INTO "role_permissions" VALUES('Viewer','telemetry.read');
INSERT INTO "role_permissions" VALUES('Viewer','status.read');
CREATE TABLE roles (
        name TEXT PRIMARY KEY CHECK(name IN ('Administrator', 'Operator', 'Viewer'))
    );
INSERT INTO "roles" VALUES('Administrator');
INSERT INTO "roles" VALUES('Operator');
INSERT INTO "roles" VALUES('Viewer');
CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY NOT NULL CHECK(length(token_hash) = 64),
        user_id TEXT NOT NULL REFERENCES users(user_id),
        created_at_epoch INTEGER NOT NULL,
        expires_at_epoch INTEGER NOT NULL CHECK(expires_at_epoch > created_at_epoch),
        revoked_at_epoch INTEGER
    );
INSERT INTO "sessions" VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','fixture-user',10,3600,NULL);
CREATE TABLE telemetry_snapshots (
                    uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
                    message_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    received_at_utc TEXT NOT NULL,
                    PRIMARY KEY(uav_id, message_type));
INSERT INTO "telemetry_snapshots" VALUES('fixture-uav','HEARTBEAT','{}','2026-01-01T00:00:00+00:00');
CREATE TABLE uav_assignments (
        user_id TEXT NOT NULL REFERENCES users(user_id),
        uav_id TEXT NOT NULL REFERENCES uavs(uav_id),
        assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id, uav_id)
    );
INSERT INTO "uav_assignments" VALUES('fixture-user','fixture-uav','2026-01-01 00:00:00');
CREATE TABLE uavs (
        uav_id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL CHECK(length(trim(name)) > 0),
        description TEXT NOT NULL DEFAULT '',
        system_id INTEGER NOT NULL UNIQUE CHECK(system_id BETWEEN 1 AND 255),
        certificate_identity TEXT NOT NULL UNIQUE,
        signing_key_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK(status IN ('pending', 'active', 'suspended', 'revoked')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
INSERT INTO "uavs" VALUES('fixture-uav','Fixture SITL','',1,'urn:sentinel:uav:1','fixture-key-id','active','2026-01-01 00:00:00');
CREATE TABLE users (
        user_id TEXT PRIMARY KEY NOT NULL,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(length(trim(username)) > 0),
        password_hash TEXT NOT NULL CHECK(password_hash LIKE '$argon2id$%'),
        role_name TEXT NOT NULL REFERENCES roles(name),
        status TEXT NOT NULL DEFAULT 'active'
            CHECK(status IN ('active', 'suspended', 'revoked')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
INSERT INTO "users" VALUES('fixture-user','fixture-admin','$argon2id$fixture-only','Administrator','active','2026-01-01 00:00:00');
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX assignments_uav ON uav_assignments(uav_id);
CREATE INDEX authorization_actor ON authorization_events(actor_id, event_id);
CREATE INDEX pending_commands ON command_requests(status, uav_id);
COMMIT;
PRAGMA user_version = 4;
