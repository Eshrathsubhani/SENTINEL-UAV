# Phase 4 protected telemetry access

Schema version three adds one latest accepted record per UAV and message type.
Registry-enabled ingestion updates telemetry_snapshots only after the active
identity mapping passes. Rejected records leave the previous snapshot intact.
The snapshot and the registry audit decision commit in the same transaction.

The backend PolicyEngine.read_telemetry requires an active authenticated account,
telemetry.read role permission, an active UAV, and an explicit assignment.
Administrator accounts require assignments too. Checks, data selection, and the
read decision audit occur in the same transaction. Revocation or assignment
removal committed before that transaction is enforced for that request.

The method raises PermissionError on denial after persisting its audit event.
An allowed request returns records with their GCS receipt timestamps.
An empty list means the UAV has no snapshots. Use the GCS receipt timestamps to assess record age. Live connectivity tracking
is a separate integration step.
The JSONL evidence files and private database remain within the trusted local
filesystem boundary. Future application interfaces must call this backend
method to enforce operator access.

Upgrade the existing database:

    python -m database.identity_database --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3"

The upgrade preserves users, sessions, UAVs, and assignments. Existing JSONL
evidence is retained. New snapshots populate from subsequent accepted records.

Read through the backend CLI:

    python -m security.authorization.policy_engine --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --uav-id UAV_ID --action telemetry.read --read-telemetry

Use --username for an Operator or Viewer account. The command prompts for the
password and closes its temporary session after the read. It never prints the
session token.

Tests cover persistence, latest-record replacement, rejected ingestion, assigned
and unassigned viewers, removal of assignments, UAV suspension, user revocation,
and migration from schema two.

Mission geolocation, command dispatch, the administrative interface, and the
remaining Phase 4 acceptance scenarios are subsequent milestones.
