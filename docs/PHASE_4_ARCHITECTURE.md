# Phase 4 — Identity and Access Control

Status — Implemented and validated. See [Phase 4 validation](PHASE_4_VALIDATION.md).

Phase 3 baseline — Commit 8c357db.

## Objective

Authenticate GCS users and authorize their access to registered UAVs,
telemetry, and supported simulated operations. Record authentication,
identity changes, and authorization decisions.

## Existing components

- Phase 3 gateway provides MAVLink signing and mutual TLS.
- Phase 2 provides the SITL telemetry source.
- security/sentinel_uav_policy.py provides the initial geolocation policy.

## Request flow

1. The user authenticates with a username and password.
2. The authentication service creates an expiring session.
3. A protected operation resolves the session to the current user.
4. The authorization service checks account status, role permissions,
   UAV status, assignment, and applicable mission conditions.
5. An allowed operation reaches its backend handler.
6. A denied operation returns a reason before dispatch.
7. The backend records the decision and its actor, action, and target.

## Identity model

Users have a stable internal user ID, a unique username, a password
hash, a role, and an account status.

Registered UAVs have a stable internal UAV ID, a display name,
a MAVLink system ID, an expected certificate URI identity,
a signing-key identifier, and a registration status.

The internal UAV ID explicitly maps to its communication credentials.
Private keys and signing secrets remain outside the identity database.

The GCS gateway retains its existing service certificate identity.
Human sessions identify the operator requesting an action.

## Roles and permissions

| Operation | Administrator | Operator | Viewer |
|---|---|---|---|
| View assigned UAV telemetry | Allow | Allow | Allow |
| Request assigned UAV status | Allow | Allow | Allow |
| Request an allowlisted simulated command | Allow | Allow | Deny |
| Create and manage users | Allow | Deny | Deny |
| Register and manage UAVs | Allow | Deny | Deny |
| Manage UAV assignments | Allow | Deny | Deny |
| View all security events | Allow | Deny | Deny |
| View own UAV access decisions | Allow | Allow | Deny |

UAV access requires an explicit assignment for every role.
Administrator permissions include managing assignments.

This assignment rule is an initial project design choice.

## Authorization rules

Deny a protected request unless all applicable checks succeed.

- The session exists, is unexpired, and has not been invalidated.
- The user account is active.
- The role permits the requested action.
- The target UAV is registered and active.
- The user has a current assignment to the UAV.
- The requested action is explicitly supported.
- Applicable mission and geolocation conditions are satisfied.

Apply geolocation conditions to designated mission actions.
Fresh position data must come from accepted telemetry associated with
the target UAV.

Evaluate current account, role, assignment, and UAV state on every
protected request.

## Authentication and sessions

- Hash passwords using Argon2id.
- Generate session tokens using cryptographically secure randomness.
- Store session token hashes with expiry and revocation state.
- Invalidate sessions on logout and account suspension or revocation.
- Track failed logins and enforce bounded login throttling.
- Keep authentication and authorization enforcement in backend services.

## Persistence and audit

Use SQLite initially for users, sessions, registered UAVs,
assignments, and security events.

Use parameterized queries, foreign keys, uniqueness constraints,
transactions, and versioned schema initialization.

Record login outcomes, identity changes, assignment changes,
and authorization decisions with UTC timestamps and actor IDs.
Exclude passwords, session tokens, private keys, and signing secrets.

## First implementation milestone

Implement persistent users, UAVs, assignments, and sessions.

Demonstrate an authenticated user requesting status for an assigned,
active UAV.

Verify denial for an invalid session, an expired session, an inactive
account, a removed assignment, and a suspended UAV.

## Later integration

Enforce registered UAV identity and status at the GCS gateway before
accepting protected telemetry.

Add an allowlisted simulated command path with authorization enforced
before MAVLink dispatch.

Integrate the basic administrative interface after backend tests pass.

## Acceptance

- Administrator, Operator, and Viewer authentication passes.
- Role and assignment restrictions are enforced.
- Revoked users and UAVs lose protected access.
- Unsupported and unauthorized commands are rejected before dispatch.
- Audit events cover the tested operations.
- Persistence and enforcement survive application restart.
- Phase 3 regression tests pass.
- Authorization latency is measured and documented.