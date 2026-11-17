# Phase 4 identity model

Users have a stable generated ID, an ASCII case-insensitive username, one of
Administrator/Operator/Viewer, an Argon2id password hash, and an account status.
A user account is active, suspended, or revoked. Suspension can be reversed.
Revocation is terminal in the implemented service.

Sessions use random bearer tokens. SQLite stores SHA-256 token hashes, their
user association, expiry, and revocation state. Logout invalidates the selected
session. Role changes, suspension, and revocation invalidate existing sessions
for the affected user.

UAVs have a stable generated ID, display name, description, MAVLink system ID,
certificate URI, signing-key fingerprint, status, and creation timestamp.
System IDs and certificate URIs are unique within this single-fleet prototype.
UAV states are pending, active, suspended, and revoked. Registration begins
pending. Revocation is terminal.

The certificate URI, signing credential fingerprint, and internal UAV ID have
an explicit mapping. A signing key's raw bytes and TLS private keys are stored
outside this database. The GCS service keeps its Phase 3 certificate identity.
Its service connection identifies the gateway. Human actions carry a separate
user session.

Assignments explicitly connect a user to a UAV. Each user/UAV pair is unique.
Administrator, Operator, and Viewer all need an assignment for protected UAV
telemetry or command access. Administrator management privileges govern
registration and assignments.

Fresh authorization queries load current identity and assignment state from
SQLite. Restarting a service preserves the stored identities and invalidations.
