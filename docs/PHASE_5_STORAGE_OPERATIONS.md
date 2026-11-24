# Phase 5 storage operations

Database schema: 10.

## Managed backup and restore

The maintenance CLI is scripts.phase5_storage_tools.

Operations require administrator authentication and authorization.
Backup and restore destinations must be new files; existing files
are never overwritten.

Copies are checked using SQLite integrity_check,
foreign_key_check and schema-version validation.
Successful operations produce a SHA-256 checksum and an audit event.

Restore creates a separate database and revokes existing sessions
in that restored copy. It does not replace the active database.

The checksum detects file changes; it is not a digital signature.
Backup creation and audit commit are separate filesystem/database
operations, not one atomic transaction.

## Operating procedure

Use the WSL Linux filesystem for the active database and backups.
Stop gateways before maintenance in this local deployment.
Do not concurrently access the active database through native
Windows SQLite.

Backup command structure:

python -m scripts.phase5_storage_tools --database ACTIVE_DB --destination NEW_BACKUP backup

Restore command structure:

python -m scripts.phase5_storage_tools --database AUTH_DB --source BACKUP --destination NEW_RESTORED_DB restore

AUTH_DB must be an available database against which the current
administrator can authenticate. Recovery when no authentication
database is available remains an offline operator procedure.

Before activating a restored copy:
- Verify its integrity, schema and required application records.
- Keep the previous database and its verified backup.
- Stop all processes using the active database.
- Explicitly configure services to use the selected restored file.
- Require fresh logins and verify authorized access.

This tool has not automatically activated a restored database.
The verified restore trial used disposable copies.

## Backup scope

The identity database backup includes its telemetry, missions,
incidents and audit records.

TLS keys/certificates, MAVLink signing keys, replay-state databases,
the separate credential-audit database, JSONL/CSV evidence and
configuration files are outside this backup's scope.

Preserve those separately with private access. Never reset replay
state merely because the identity database was restored.

## Research retention policy

Retain telemetry, security events, mission records, incidents,
notes, audit history and experiment evidence through mentor review
and final research submission.

No automatic deletion is enabled in this phase. After submission,
review archival and deletion requirements before changing policy.
Do not delete evidence referenced by incidents or mission records.

Create a verified backup before migrations or maintenance.
Keep milestone backups and the previous verified recovery point.
Store an additional protected copy on a separate device; that
off-device copy has not yet been verified in this validation.

Keep databases, backups and credentials outside Git.
Database encryption at rest is not implemented or claimed.

## Verification

Managed backup and restore passed on disposable WSL databases.
Restore reported sessions_revoked=true.

Nine automated maintenance tests passed on Windows:
- Verified backup and unchanged source
- Session revocation only in the restored destination
- Existing-destination protection
- Missing-source handling
- Corrupt-source rejection and cleanup
- Unsupported-schema rejection
- Foreign-key corruption rejection
- Verification-failure cleanup
- Viewer denial through the maintenance CLI

The existing regression run passed 181 tests and 99 subtests.
After correcting test connection cleanup, the nine new tests
passed separately. A combined final regression run remains due.

See PHASE_5_RELIABILITY_VALIDATION.md for restore comparison,
read-performance and mixed-access evidence.