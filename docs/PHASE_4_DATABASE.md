# Phase 4 identity database

Schema version one supplies users, roles, permissions, role permissions, UAVs,
assignments, sessions, policies, identity events, and authorization events.

Use the standard-library SQLite driver for this initial schema. Every application
connection must use connect_database so foreign keys are enabled. Initialization
takes a write lock and commits schema creation and permission seeds together.
Repeated initialization preserves data. Unknown versions and unrelated databases
are rejected. Future schema changes require explicit version migrations.

Each user has one role, matching the Phase 4 architecture. UAV system IDs are
unique within this initial single-fleet deployment. Usernames are case insensitive
for ASCII names. The authentication service will define accepted username inputs.

Only Argon2id hashes belong in password_hash. The schema prefix constraint is a
format guard. The authentication service must generate and validate the actual
hash. Sessions store token hashes and epoch timestamps. Authorization services
must check expiry, account status, permissions, and current assignments.

Event actor and target IDs are historical text, allowing rejected unknown
identities and retention after lifecycle changes. Policy JSON validation and
authorization enforcement belong to the upcoming service implementation.

Run from the repository root in Windows Command Prompt:

    python -m database.identity_database --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3"

Use a private local account directory. Keep the SQLite database out of Git.
Initialization creates no accounts or credentials. This milestone provides the
schema and tests. Login, role enforcement, lifecycle services, and the gateway
registry integration follow in subsequent milestones.
