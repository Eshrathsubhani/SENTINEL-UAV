# Phase 4 resource authorization

PolicyEngine.authorize resolves a current session, checks the role's permission,
requires an active registered UAV, and checks an explicit user-to-UAV assignment.
Administrator accounts require assignments too. Unsupported actions are denied.

Each request records actor, resource, action, allow/deny, reason, and UTC timestamp
in authorization_events. Invalid sessions are recorded without a resolved actor.
Tokens and passwords are excluded. A database failure propagates to the caller,
so it must not proceed with an operation when authorization raises an error.

This implements role permission checks and contextual checks for current account
state, session expiry, UAV status, and assignment. Current state is read on every
call, including requests made using previously issued sessions. No schema upgrade
is needed.

Supported actions are telemetry.read, status.read, and command.rtl. The first two
require their matching permissions. command.rtl requires command.request.

The CLI is a decision check and sends no MAVLink command. It logs in at a hidden
password prompt, prints ALLOW or DENY, and logs out. A deny returns exit code one.

Example from Windows Command Prompt:

    python -m security.authorization.policy_engine --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --uav-id UAV_ID --action status.read

Replace UAV_ID with the internal registry ID. Use --username for another account.

Pending integrations are protected telemetry handlers, authenticated UAV lookup
in the gateway, and command dispatch. Geolocation policy applies later to the
designated mission actions. A decision is valid for the evaluated state and
time. Future dispatch must recheck authorization immediately before execution.
Do not cache an allow decision as continuing permission.
