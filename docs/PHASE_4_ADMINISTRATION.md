# Phase 4 administration console

Run this local console from the Windows repository root:

    python -m streamlit run phase4_access_app.py --server.address 127.0.0.1

Sign in with the administrator created through bootstrap-admin. The default
database is %USERPROFILE%/.sentinel-uav/identity.sqlite3. To use another private
database, set SENTINEL_IDENTITY_DB in the server environment before starting.

The Administrator can create users, change roles and account status, register
UAVs, update UAV status, manage assignments, and view audit records. Role changes
invalidate all current sessions for the affected account. Suspension and
revocation retain the existing session invalidation behavior.

Operators see only their assigned active UAVs and their own audit events.
Viewers see assigned telemetry. Supported simulated status requests still
require command permission and are rechecked by the dispatcher.

The UI reads the current account on every rerun. Every management service
rechecks administrator identity in the same transaction as its operation.
Denied administrator operations are persisted as authorization events.
Audit retrieval is read-only, scoped by backend permissions, and limited to
the latest hundred entries from each event table per request.

Console telemetry uses PolicyEngine.read_telemetry. A user cannot gain access by
changing a visible selection because the backend rechecks their assignment.
The private database and evidence files remain within the trusted OS-account
boundary. Application permissions protect service operations. Protection from
a hostile process that can edit the SQLite file requires OS-level isolation.

Passwords are hidden in form fields and cleared after submission. Session tokens
stay in server-side session state and are never displayed. Logging out revokes
the current backend session. Other valid sessions retain their normal expiry.

The console is the initial Phase 4 administrative interface. Full dashboard
integration and visual refinement belong to Phase 8. It is intended for local
loopback validation.

Tests cover backend role changes, invalidation of existing sessions, management
denials and audit persistence, audit visibility, assignment-scoped discovery,
administrator login and user creation through the app, logout, Viewer controls,
and UI session termination after revocation.
