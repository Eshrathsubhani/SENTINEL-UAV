# Phase 5.2 — Database connection and migration foundation

Status: Implemented; available-source Linux checks passed. Full Windows validation pending.

## Changes

- `database/connection.py` owns the shared connection function and transaction context manager.
- Every connection enables and checks foreign-key enforcement. Connections return named rows and default to a ten-second busy timeout.
- Write transactions begin with BEGIN IMMEDIATE; read transactions use BEGIN. Success commits; failure rolls back; either outcome closes the connection. SQLite errors propagate without automatically replaying an operation.
- `database/schema_v1.py` freezes the original schema and role-permission definitions.
- `database/migrations.py` lists explicit version-1–4 migrations. The initializer runs all pending steps inside one transaction and updates user_version after each successful step within that transaction. A failure rolls back the complete upgrade.
- `database/identity_database.py` retains its existing CLI and import interface, including connect_database, initialize_database, SCHEMA_VERSION, SCHEMA and PERMISSIONS.
- Authentication uses the shared transaction helper. Registry and other services can continue using the compatibility connection function and their existing transactions.

The application data layout remains schema version 4. No history, mission, incident, backup scheduling, HTTP API or encryption feature is introduced by this patch. Journal mode is not changed.

## Preservation and validation

The synthetic SQL fixture was generated using the original Phase 4 initializer. It contains fake users, UAVs, assignments, sessions, policies, identity/authorization events, login attempts, snapshots and command requests; it contains no real passwords, session tokens or keys.

Eight new tests verify:

1. Repeated initialization leaves every row and schema definition in the populated original version-4 fixture unchanged.
2. Version-1, version-2 and version-3 layouts upgrade while preserving their existing rows.
3. A failed final migration rolls back DDL, data changes and schema version; a subsequent normal retry succeeds.
4. A failure after multiple migration steps rolls the entire new database back to version 0.
5. A foreign-key failure rolls back preceding writes and releases the connection.
6. Writer contention fails at the configured timeout without applying changes.
7. Calling the migration runner without an explicit transaction fails.
8. Connections are closed after both successful and failed transactions.

Existing tests additionally cover concurrent initialization, unsupported future schemas, unrelated databases and Phase 3/4 behavior. The helper supplies connection/transaction handling, not authorization; protected services still enforce sessions, roles and assignments.

## Windows verification

Keep the verified pre-Phase-5 backup outside Git. Apply the patch once, then run:

```bat
python -m pytest -q
python -m database.identity_database --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3"
git diff --check
git status --short
```

Local verification passed 79 tests and 24 subtests after excluding the two Streamlit UI tests: the supplied review ZIP does not include their required root file, phase4_access_app.py. The initial all-tests run had 79 passes and two missing-file failures. The full Windows suite is expected to report 81 tests and 24 subtests with the same baseline and dependencies; Windows results must be recorded separately. Initialization should report schema 4. No SITL rerun is required for this refactoring.

Do not commit local databases, backups or the duplicate extraction folder. Signing watermark and credential-audit databases are untouched. A verified backup integrity check is not a complete restore drill; the later backup/recovery stage must test restoration and anti-rollback requirements.

## Next stage

Add telemetry history and mission relationships through new incremental migrations, preserving existing latest-snapshot and authorization behavior. Continue using caller-owned transactions for logical operations that must commit together.
